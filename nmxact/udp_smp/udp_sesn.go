/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package udp_smp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/joaojeronimo/go-crc16"
	"github.com/runtimeco/go-coap"
	log "github.com/sirupsen/logrus"

	"mynewt.apache.org/newt/util"
	"mynewt.apache.org/newtmgr/nmxact/mgmt"
	"mynewt.apache.org/newtmgr/nmxact/nmcoap"
	"mynewt.apache.org/newtmgr/nmxact/nmp"
	"mynewt.apache.org/newtmgr/nmxact/nmxutil"
	"mynewt.apache.org/newtmgr/nmxact/omp"
	"mynewt.apache.org/newtmgr/nmxact/sesn"
)

type UdpSesn struct {
	cfg  sesn.SesnCfg
	addr *net.UDPAddr
	conn *net.UDPConn
	txvr *mgmt.Transceiver
}

func NewUdpSesn(cfg sesn.SesnCfg) (*UdpSesn, error) {
	s := &UdpSesn{
		cfg: cfg,
	}
	txvr, err := mgmt.NewTransceiver(cfg.TxFilter, cfg.RxFilter, false,
		cfg.MgmtProto, 3)
	if err != nil {
		return nil, err
	}
	s.txvr = txvr

	return s, nil
}

func (s *UdpSesn) Open() error {
	if s.conn != nil {
		return nmxutil.NewSesnAlreadyOpenError(
			"Attempt to open an already-open UDP session")
	}

	conn, addr, err := Listen(s.cfg.PeerSpec.Udp,
		func(data []byte) {
			for {
				if len(data) > 1 && data[0] == '\r' {
					data = data[1:]
				} else {
					break
				}
			}
			log.Debugf("Rx serial:\n%s", hex.Dump(data))
			if len(data) < 2 || ((data[0] != 4 || data[1] != 20) &&
				(data[0] != 6 || data[1] != 9)) {
				return
			}

			base64Data := string(data[2:])

			d, err := base64.StdEncoding.DecodeString(base64Data)
			if err != nil {
				fmt.Errorf("Couldn't decode base64 string:"+
					" %s\nPacket hex dump:\n%s",
					base64Data, hex.Dump(data))
				return
			}

			var pkt *Packet

			if data[0] == 6 && data[1] == 9 {
				if len(d) < 2 {
					return
				}

				pktLen := binary.BigEndian.Uint16(d[0:2])
				pkt, err = NewPacket(pktLen)
				if err != nil {
					return
				}
				d = d[2:]
			}

			full := pkt.AddBytes(d)
			if full {
				if crc16.Crc16(pkt.GetBytes()) != 0 {
					fmt.Errorf("CRC error")
					return
				}

				/*
				 * Trim away the 2 bytes of CRC
				 */
				pkt.TrimEnd(2)
				b := pkt.GetBytes()
				pkt = nil

				log.Debugf("Decoded input:\n%s", hex.Dump(b))

				s.txvr.DispatchNmpRsp(b)
			}
		})
	if err != nil {
		return err
	}

	s.addr = addr
	s.conn = conn
	return nil
}

func (s *UdpSesn) Close() error {
	if s.conn == nil {
		return nmxutil.NewSesnClosedError(
			"Attempt to close an unopened UDP session")
	}

	s.conn.Close()
	s.txvr.ErrorAll(fmt.Errorf("closed"))
	s.txvr.Stop()
	s.conn = nil
	s.addr = nil
	return nil
}

func (s *UdpSesn) IsOpen() bool {
	return s.conn != nil
}

func (s *UdpSesn) MtuIn() int {
	return MAX_PACKET_SIZE -
		omp.OMP_MSG_OVERHEAD -
		nmp.NMP_HDR_SIZE
}

func (s *UdpSesn) MtuOut() int {
	return MAX_PACKET_SIZE -
		omp.OMP_MSG_OVERHEAD -
		nmp.NMP_HDR_SIZE
}

func (s *UdpSesn) TxRxMgmt(m *nmp.NmpMsg,
	timeout time.Duration) (nmp.NmpRsp, error) {

	if !s.IsOpen() {
		return nil, fmt.Errorf("Attempt to transmit over closed UDP session")
	}

	txRaw := func(b []byte) error {
		pktData := make([]byte, 2)

		crc := crc16.Crc16(b)
		binary.BigEndian.PutUint16(pktData, crc)
		b = append(b, pktData...)

		dLen := uint16(len(b))
		binary.BigEndian.PutUint16(pktData, dLen)
		pktData = append(pktData, b...)

		base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(pktData)))

		base64.StdEncoding.Encode(base64Data, pktData)

		written := 0
		totlen := len(base64Data)

		for written < totlen {
			/* write the packet stat designators. They are
			 * different whether we are starting a new packet or continuing one */
			if written == 0 {
				s.conn.WriteToUDP([]byte{6, 9}, s.addr)
			} else {
				/* slower platforms take some time to process each segment
				 * and have very small receive buffers.  Give them a bit of
				 * time here */
				time.Sleep(20 * time.Millisecond)
				s.conn.WriteToUDP([]byte{4, 20}, s.addr)
			}

			/* ensure that the total frame fits into 128 bytes.
			 * base 64 is 3 ascii to 4 base 64 byte encoding.  so
			 * the number below should be a multiple of 4.  Also,
			 * we need to save room for the header (2 byte) and
			 * carriage return (and possibly LF 2 bytes), */

			/* all totaled, 124 bytes should work */
			writeLen := util.Min(124, totlen-written)

			writeBytes := base64Data[written : written+writeLen]
			s.conn.WriteToUDP(writeBytes, s.addr)
			s.conn.WriteToUDP([]byte{'\n'}, s.addr)

			written += writeLen
		}

		return nil
	}
	return s.txvr.TxRxMgmt(txRaw, m, s.MtuOut(), timeout)
}

func (s *UdpSesn) TxRxMgmtAsync(m *nmp.NmpMsg,
	timeout time.Duration, ch chan nmp.NmpRsp, errc chan error) error {
	rsp, err := s.TxRxMgmt(m, timeout)
	if err != nil {
		errc <- err
	} else {
		ch <- rsp
	}
	return nil
}

func (s *UdpSesn) AbortRx(seq uint8) error {
	s.txvr.ErrorAll(fmt.Errorf("Rx aborted"))
	return nil
}

func (s *UdpSesn) TxCoap(m coap.Message) error {
	txRaw := func(b []byte) error {
		_, err := s.conn.WriteToUDP(b, s.addr)
		return err
	}

	return s.txvr.TxCoap(txRaw, m, s.MtuOut())
}

func (s *UdpSesn) MgmtProto() sesn.MgmtProto {
	return s.cfg.MgmtProto
}

func (s *UdpSesn) ListenCoap(mc nmcoap.MsgCriteria) (*nmcoap.Listener, error) {
	return s.txvr.ListenCoap(mc)
}

func (s *UdpSesn) StopListenCoap(mc nmcoap.MsgCriteria) {
	s.txvr.StopListenCoap(mc)
}

func (s *UdpSesn) CoapIsTcp() bool {
	return false
}

func (s *UdpSesn) RxAccept() (sesn.Sesn, *sesn.SesnCfg, error) {
	return nil, nil, fmt.Errorf("Op not implemented yet")
}

func (s *UdpSesn) RxCoap(opt sesn.TxOptions) (coap.Message, error) {
	return nil, fmt.Errorf("Op not implemented yet")
}

func (s *UdpSesn) Filters() (nmcoap.TxMsgFilter, nmcoap.RxMsgFilter) {
	return s.txvr.Filters()
}

func (s *UdpSesn) SetFilters(txFilter nmcoap.TxMsgFilter,
	rxFilter nmcoap.RxMsgFilter) {

	s.txvr.SetFilters(txFilter, rxFilter)
}
