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
	"bytes"
)

type Packet struct {
	expectedLen uint16
	buffer      *bytes.Buffer
}

func NewPacket(expectedLen uint16) (*Packet, error) {
	pkt := &Packet{
		expectedLen: expectedLen,
		buffer:      bytes.NewBuffer([]byte{}),
	}

	return pkt, nil
}

func (pkt *Packet) AddBytes(bytes []byte) bool {
	pkt.buffer.Write(bytes)
	if pkt.buffer.Len() >= int(pkt.expectedLen) {
		return true
	} else {
		return false
	}
}

func (pkt *Packet) GetBytes() []byte {
	return pkt.buffer.Bytes()
}

func (pkt *Packet) TrimEnd(count int) {

	if pkt.buffer.Len() < count {
		count = pkt.buffer.Len()
	}
	pkt.buffer.Truncate(pkt.buffer.Len() - count)
}
