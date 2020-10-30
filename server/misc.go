// Copyright (c) 2014 The SurgeMQ Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"gmqs/message"
)

var (
	ErrInvalidConnectionType  error = errors.New("service: Invalid connection type")
	ErrInvalidSubscriber      error = errors.New("service: Invalid subscriber")
	ErrBufferNotReady         error = errors.New("service: buffer is not ready")
	ErrBufferInsufficientData error = errors.New("service: buffer has insufficient data.")
)

const (
	DefaultKeepAlive        = 300
	DefaultConnectTimeout   = 2
	DefaultAckTimeout       = 20
	DefaultTimeoutRetries   = 3
	DefaultSessionsProvider = "mem"
	DefaultAuthenticator    = "mockSuccess"
	DefaultTopicsProvider   = "mem"
)

func getConnectMessage(conn io.Closer) (*message.ConnectMessage, error) {
	buf, err := getMessageBuffer(conn)
	if err != nil {
		//glog.Debugf("Receive error: %v", err)
		return nil, err
	}

	msg := message.NewConnectMessage()

	_, err = msg.Decode(buf) //解析包
	//glog.Debugf("Received: %s", msg)
	return msg, err
}

func getConnackMessage(conn io.Closer) (*message.ConnackMessage, error) {
	buf, err := getMessageBuffer(conn)
	if err != nil {
		//glog.Debugf("Receive error: %v", err)
		return nil, err
	}

	msg := message.NewConnackMessage()

	_, err = msg.Decode(buf)
	//glog.Debugf("Received: %s", msg)
	return msg, err
}

func writeMessage(conn io.Closer, msg message.Message) error {
	buf := make([]byte, msg.Len())
	_, err := msg.Encode(buf)
	if err != nil {
		//glog.Debugf("Write error: %v", err)
		return err
	}
	//glog.Debugf("Writing: %s", msg)

	return writeMessageBuffer(conn, buf)
}

func getMessageBuffer(c io.Closer) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidConnectionType
	}

	conn, ok := c.(net.Conn)
	if !ok {
		return nil, ErrInvalidConnectionType
	}

	var (
		// the message buffer
		buf []byte

		// tmp buffer to read a single byte
		b []byte = make([]byte, 1)

		// total bytes read
		l int = 0
	)

	// Let's read enough bytes to get the message header (msg type, remaining length)
	for {
		// If we have read 5 bytes and still not done, then there's a problem.
		if l > 5 { //最多5个字节，第1个字节固定包头，后面是最多4个字节的剩余长度
			return nil, fmt.Errorf("connect/getMessage: 4th byte of remaining length has continuation bit set")
		}

		n, err := conn.Read(b[0:])
		if err != nil {
			//glog.Debugf("Read error: %v", err)
			return nil, err
		}

		// Technically i don't think we will ever get here
		if n == 0 {
			continue
		}

		buf = append(buf, b...)
		l += n

		// Check the remlen byte (1+) to see if the continuation bit is set. If so,
		// increment cnt and continue reading. Otherwise break.
		if l > 1 && b[0] < 0x80 { //第二个字节以后是长度，0x80二进制为10000000, 如果最高位为1表示长度还要继续
			break
		}
	}

	// Get the remaining length of the message
	remlen, _ := binary.Uvarint(buf[1:])
	buf = append(buf, make([]byte, remlen)...)

	//因为这个方法只在connect时才被调用，所以要一直读取到整个connect包
	for l < len(buf) { //继续读取剩余长度直到读取所有长度，这样才是一个完整的mqtt包
		n, err := conn.Read(buf[l:])
		if err != nil {
			return nil, err
		}
		l += n
	}

	return buf, nil
}

func writeMessageBuffer(c io.Closer, b []byte) error {
	if c == nil {
		return ErrInvalidConnectionType
	}

	conn, ok := c.(net.Conn)
	if !ok {
		return ErrInvalidConnectionType
	}

	_, err := conn.Write(b)
	return err
}

// Copied from http://golang.org/src/pkg/net/timeout_test.go
func isTimeout(err error) bool {
	e, ok := err.(net.Error)
	return ok && e.Timeout()
}
