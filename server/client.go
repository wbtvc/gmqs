// Copyright 2012-2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use c file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"gmqs/glog"
	"gmqs/message"
	"gmqs/sessions"
	"gmqs/topics"
)

// Type of client connection.
const (
	// CLIENT is an end user.
	CLIENT = iota
	// ROUTER is another router in the cluster.
	ROUTER
)

const (
	// Original Client protocol from 2009.
	// http://nats.io/documentation/internals/nats-protocol/
	ClientProtoZero = iota
	// This signals a client can receive more then the original INFO block.
	// This can be used to update clients on other cluster members, etc.
	ClientProtoInfo
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const (
	// Scratch buffer size for the processMsg() calls.
	msgScratchSize = 512
	msgHeadProto   = "MSG "
)

// For controlling dynamic buffer sizes.
const (
	startBufSize = 512 // For INFO/CONNECT block
	minBufSize   = 128
	maxBufSize   = 65536
)

// Represent client booleans with a bitmask
type clientFlag byte

// Some client state represented as flags
const (
	connectReceived   clientFlag = 1 << iota // The CONNECT proto has been received
	firstPongSent                            // The first PONG has been sent
	handshakeComplete                        // For TLS clients, indicate that the handshake is complete
)

// set the flag (would be equivalent to set the boolean to true)
func (cf *clientFlag) set(c clientFlag) {
	*cf |= c
}

// isSet returns true if the flag is set, false otherwise
func (cf clientFlag) isSet(c clientFlag) bool {
	return cf&c != 0
}

// setIfNotSet will set the flag `c` only if that flag was not already
// set and return true to indicate that the flag has been set. Returns
// false otherwise.
func (cf *clientFlag) setIfNotSet(c clientFlag) bool {
	if *cf&c == 0 {
		*cf |= c
		return true
	}
	return false
}

type client struct {
	// Here first because of use of atomics, and memory alignment.
	stats
	mpay  int64 //payload最大长度，默认为1k
	mu    sync.Mutex
	typ   int        //CLIENT还是ROUTER
	cid   uint64     //clientid,全局唯一自增
	opts  clientOpts //服务器设置
	start time.Time  //client启动时间
	nc    net.Conn
	ncs   string
	bw    *bufio.Writer //写缓存
	srv   *Server
	subs  map[string]*subscription //订阅的队列
	perms *permissions             //权限控制
	cache readCache

	pcd  map[*client]struct{} //pcd: 当有send动作时，就把client指针加入到这个map中，这是因为发数据用到了bw，不是立即发送，保存指针是为了调用flush真正发送数据
	atmr *time.Timer          //auth超时检测
	ptmr *time.Timer          //ping检测定时器
	pout int                  //pong超时计数
	wfc  int                  //一个缓存不足情况的计数器，用来调节缓存大小
	msgb [msgScratchSize]byte
	last time.Time //最后活跃时间
	parseState

	route *route
	debug bool
	trace bool

	flags clientFlag // Compact booleans into a single field. Size will be increased when needed.

	kicked bool //wbt
	// Session manager for tracking all the clients
	sessMgr *sessions.Manager
	// Topics manager for all the client subscriptions
	topicsMgr *topics.Manager
	// sess is the session object for c MQTT session. It keeps track session variables
	// such as ClientId, KeepAlive, Username, etc
	sess  *sessions.Session
	subs2 []interface{}
	qoss  []byte
	rmsgs []*message.PublishMessage
	//onpub  OnPublishFunc
	closed  int64
	done    chan struct{}
	isLogin bool
}

type permissions struct {
	sub    *Sublist
	pub    *Sublist
	pcache map[string]bool
}

const (
	maxResultCacheSize = 512
	maxPermCacheSize   = 32
	pruneSize          = 16
)

// Used in readloop to cache hot subject lookups and group statistics.
type readCache struct {
	genid   uint64
	results map[string]*SublistResult
	prand   *rand.Rand //用来随机选择一个qsub
	inMsgs  int
	inBytes int
	subs    int
}

func (c *client) String() (id string) {
	return c.ncs
}

func (c *client) GetOpts() *clientOpts {
	return &c.opts
}

// GetTLSConnectionState returns the TLS ConnectionState if TLS is enabled, nil
// otherwise. Implements the ClientAuth interface.
func (c *client) GetTLSConnectionState() *tls.ConnectionState {
	tc, ok := c.nc.(*tls.Conn)
	if !ok {
		return nil
	}
	state := tc.ConnectionState()
	return &state
}

type subscription struct {
	client  *client
	subject []byte
	queue   []byte
	sid     []byte
	nm      int64
	max     int64
}

type clientOpts struct {
	Verbose       bool   `json:"verbose"`
	Pedantic      bool   `json:"pedantic"`
	TLSRequired   bool   `json:"tls_required"`
	Authorization string `json:"auth_token"`
	Username      string `json:"user"`
	Password      string `json:"pass"`
	Name          string `json:"name"`
	Lang          string `json:"lang"`
	Version       string `json:"version"`
	Protocol      int    `json:"protocol"`

	// The number of seconds to keep the connection live if there's no data.
	// If not set then default to 5 mins.
	keepAlive int
	// The number of seconds to wait for the CONNECT message before disconnecting.
	// If not set then default to 2 seconds.
	ConnectTimeout int

	// The number of seconds to wait for any ACK messages before failing.
	// If not set then default to 20 seconds.
	AckTimeout int

	// The number of times to retry sending a packet if ACK is not received.
	// If no set then default to 3 retries.
	TimeoutRetries int
}

var defaultOpts = clientOpts{Verbose: true, Pedantic: true}

var (
	errDisconnect = errors.New("Disconnect")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Lock should be held
func (c *client) initClient() {
	c.typ = CLIENT
	s := c.srv
	c.cid = atomic.AddUint64(&s.gcid, 1)
	c.bw = bufio.NewWriterSize(c.nc, startBufSize)
	c.subs = make(map[string]*subscription)
	c.debug = (atomic.LoadInt32(&c.srv.logging.debug) != 0)
	c.trace = (atomic.LoadInt32(&c.srv.logging.trace) != 0)

	// This is a scratch buffer used for processMsg()
	// The msg header starts with "MSG ",
	// in bytes that is [77 83 71 32].
	c.msgb = [msgScratchSize]byte{77, 83, 71, 32}

	// This is to track pending clients that have data to be flushed
	// after we process inbound msgs from our own connection.
	c.pcd = make(map[*client]struct{})

	// snapshot the string version of the connection
	conn := "-"
	if ip, ok := c.nc.(*net.TCPConn); ok {
		addr := ip.RemoteAddr().(*net.TCPAddr)
		conn = fmt.Sprintf("%s:%d", addr.IP, addr.Port)
	}

	switch c.typ {
	case CLIENT:
		c.ncs = fmt.Sprintf("%s - cid:%d", conn, c.cid)
	case ROUTER:
		c.ncs = fmt.Sprintf("%s - rid:%d", conn, c.cid)
	}
}

// RegisterUser allows auth to call back into a new client
// with the authenticated user. This is used to map any permissions
// into the client.
func (c *client) RegisterUser(user *User) {
	if user.Permissions == nil {
		// Reset perms to nil in case client previously had them.
		c.mu.Lock()
		c.perms = nil
		c.mu.Unlock()
		return
	}

	// Process Permissions and map into client connection structures.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Pre-allocate all to simplify checks later.
	c.perms = &permissions{}
	c.perms.sub = NewSublist()
	c.perms.pub = NewSublist()
	c.perms.pcache = make(map[string]bool)

	// Loop over publish permissions
	for _, pubSubject := range user.Permissions.Publish {
		sub := &subscription{subject: []byte(pubSubject)}
		c.perms.pub.Insert(sub)
	}

	// Loop over subscribe permissions
	for _, subSubject := range user.Permissions.Subscribe {
		sub := &subscription{subject: []byte(subSubject)}
		c.perms.sub.Insert(sub)
	}
}

const (
	minKeepAlive = 30
)

// var (
// 	gsvcid uint64 = 0
// )

func (c *client) getSession(s *Server, req *message.ConnectMessage, resp *message.ConnackMessage) error {
	// If CleanSession is set to 0, the server MUST resume communications with the
	// client based on state from the current session, as identified by the client
	// identifier. If there is no session associated with the client identifier the
	// server must create a new session.
	//
	// If CleanSession is set to 1, the client and server must discard any previous
	// session and start a new one. This session lasts as long as the network c
	// onnection. State data associated with c session must not be reused in any
	// subsequent session.

	var err error

	// Check to see if the client supplied an ID, if not, generate one and set
	// clean session.
	if len(req.ClientId()) == 0 {
		req.SetClientId([]byte(fmt.Sprintf("internalclient%d", c.cid)))
		req.SetCleanSession(true)
	}

	clientid := string(req.ClientId())

	// If CleanSession is NOT set, check the session store for existing session.
	// If found, return it.
	if !req.CleanSession() {
		if c.sess, err = s.sessMgr.Get(clientid); err == nil {
			resp.SetSessionPresent(true)

			if err := c.sess.Update(req); err != nil { //更新保存connect消息到变量中
				return err
			}
		}
	}

	// If CleanSession, or no existing session found, then create a new one
	if c.sess == nil { //创建新的session
		if c.sess, err = s.sessMgr.New(clientid); err != nil {
			return err
		}

		resp.SetSessionPresent(false)

		if err := c.sess.Init(req); err != nil {
			return err
		}
	}

	return nil
}

func (c *client) checkConnect(s *Server, conn net.Conn, srvopts *Options) error {
	srvopts.ConnectTimeout = 2
	conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(srvopts.ConnectTimeout)))

	resp := message.NewConnackMessage() //用来ack connect

	req, err := getConnectMessage(conn) //接收connect包
	if err != nil {
		c.Errorf("checkConnect:%v", err)
		if cerr, ok := err.(message.ConnackCode); ok {
			//glog.Debugf("request   message: %s\nresponse message: %s\nerror           : %v", mreq, resp, err)
			resp.SetReturnCode(cerr)
			resp.SetSessionPresent(false)
			writeMessage(conn, resp)
		}
		return err
	}
	conn.SetReadDeadline(time.Time{})

	c.mu.Lock()
	// If we can't stop the timer because the callback is in progress...
	if !c.clearAuthTimer() {
		// wait for it to finish and handle sending the failure back to
		// the client.
		for c.nc != nil {
			c.mu.Unlock()
			time.Sleep(25 * time.Millisecond)
			c.mu.Lock()
		}
		c.mu.Unlock()
		return nil
	}
	c.last = time.Now()
	// Indicate that the CONNECT protocol has been received, and that the
	// server now knows which protocol c client supports.
	c.flags.set(connectReceived)
	c.mu.Unlock()

	if s != nil {
		// Check for Auth
		c.opts.Username = string(req.Username())
		c.opts.Password = string(req.Password())
		if ok := s.checkAuthorization(c); !ok {
			resp.SetReturnCode(message.ErrBadUsernameOrPassword)
			resp.SetSessionPresent(false)
			writeMessage(conn, resp)
			return ErrAuthorization
		}
	}

	if req.KeepAlive() == 0 {
		req.SetKeepAlive(minKeepAlive)
	}

	// c.id = atomic.AddUint64(&gsvcid, 1)

	c.opts.keepAlive = int(req.KeepAlive())
	c.opts.ConnectTimeout = srvopts.ConnectTimeout
	c.opts.AckTimeout = srvopts.AckTimeout
	c.opts.TimeoutRetries = srvopts.TimeoutRetries
	c.sessMgr = s.sessMgr
	c.topicsMgr = s.topicsMgr

	err = c.getSession(s, req, resp)
	if err != nil {
		return err
	}

	resp.SetReturnCode(message.ConnectionAccepted)

	if err = writeMessage(conn, resp); err != nil { //ack
		return err
	}

	// svc.inStat.increment(int64(req.Len()))
	// svc.outStat.increment(int64(resp.Len()))
	return nil
}

// peekMessageSize() reads, but not commits, enough bytes to determine the size of
// the next message and returns the type and size.
func (c *client) peekMessageSize(br *bufio.Reader) (message.MessageType, int, error) {
	var (
		b   []byte
		err error
		cnt int = 2
	)

	// Let's read enough bytes to get the message header (msg type, remaining length)
	for {
		// If we have read 5 bytes and still not done, then there's a problem.
		if cnt > 5 {
			return 0, 0, fmt.Errorf("sendrecv/peekMessageSize: 4th byte of remaining length has continuation bit set")
		}

		// Peek cnt bytes from the input buffer.
		b, err = br.Peek(cnt) //读取数据后in的cursor指针不动
		if err != nil {
			// c.Errorf("Peek:%v", err)
			return 0, 0, err
		}

		// If not enough bytes are returned, then continue until there's enough.
		if len(b) < cnt {
			continue
		}

		// If we got enough bytes, then check the last byte to see if the continuation
		// bit is set. If so, increment cnt and continue peeking
		if b[cnt-1] >= 0x80 {
			cnt++
		} else {
			break
		}
	}

	// Get the remaining length of the message
	remlen, m := binary.Uvarint(b[1:])

	// Total message length is remlen + 1 (msg type) + m (remlen bytes)
	total := int(remlen) + 1 + m //包全长

	mtype := message.MessageType(b[0] >> 4) //固定报头的控制报文类型

	return mtype, total, err
}

// peekMessage() reads a message from the buffer, but the bytes are NOT committed.
// This means the buffer still thinks the bytes are not read yet.
func (c *client) peekMessage(br *bufio.Reader, mtype message.MessageType, total int) (message.Message, int, error) {
	var (
		b    []byte
		err  error
		i, n int
		msg  message.Message
	)

	// Peek until we get total bytes
	for i = 0; ; i++ { //读取包的所有数据
		// Peek remlen bytes from the input buffer.
		b, err = br.Peek(total)
		if err != nil && err != bufio.ErrBufferFull {
			return nil, 0, err
		}

		// If not enough bytes are returned, then continue until there's enough.
		if len(b) >= total {
			break
		}
	}

	msg, err = mtype.New()
	if err != nil {
		return nil, 0, err
	}

	n, err = msg.Decode(b)
	return msg, n, err
}

func (c *client) onstart() error {
	// c.onpub = func(msg *message.PublishMessage) error {
	// 	if err := c.publishToClient(msg, nil); err != nil {
	// 		glog.Errorf("client/onPublish: Error publishing message: %v", err)
	// 		return err
	// 	}

	// 	return nil
	// }

	// If c is a recovered session, then add any topics it subscribed before
	topics, qoss, err := c.sess.Topics() //可能是旧的session，获取订阅表
	if err != nil {
		return err
	} else {
		for i, t := range topics { //重新订阅
			c.topicsMgr.Subscribe([]byte(t), qoss[i], c) //&c.onpub)
		}
	}
	return nil
}

func (c *client) onLogin() {
	if c.isLogin {
		return
	}
	c.isLogin = true

}
func (c *client) onLogout() {
	if !c.isLogin {
		return
	}
	c.isLogin = false

}

func (c *client) readLoop() {

	// Grab the connection off the client, it will be cleared on a close.
	// We check for that after the loop, but want to avoid a nil dereference
	c.mu.Lock()
	nc := c.nc
	s := c.srv
	defer func() {
		c.onLogout()
		s.grWG.Done()
	}()
	c.mu.Unlock()

	if nc == nil {
		return
	}

	c.Noticef("runtime.NumGoroutine(): %v", runtime.NumGoroutine())

	// Snapshot server options.
	opts := s.getOpts()

	if err := c.checkConnect(s, nc, opts); err != nil {
		c.closeConnection()
		c.Noticef("connect error: %v", err)
		return
	}

	if err := c.onstart(); err != nil {
		c.closeConnection()
		return
	}
	c.onLogin() //wbt: login info save to db
	// Start read buffer.
	// b := make([]byte, startBufSize)
	br := bufio.NewReaderSize(nc, startBufSize*2)

	keepAlive := time.Second * time.Duration(c.opts.keepAlive)
	d := keepAlive + (keepAlive / 2)
	c.Noticef("keepalive:%v", d)
	for {

		c.nc.SetReadDeadline(time.Now().Add(d))
		// 1. Find out what message is next and the size of the message
		mtype, total, err := c.peekMessageSize(br) //获取固定包头及剩余长度
		if err != nil {
			c.Errorf("peekMessageSize:%v", err)
			// glog.Errorf("(%s) Error peek header error: %v", c.getcid(), err)
			c.closeConnection()
			return
		}

		if total > startBufSize {
			c.Errorf("Error total is too large: %d", total)
			c.closeConnection()
			return
		}

		msg, n, err := c.peekMessage(br, mtype, total) //in的cursor未移动所以读取包所有字节total
		if err != nil {
			c.Errorf("peekMessage:%v", err)
			c.closeConnection()
			return
		}

		// // 5. Process the read message
		// err = c.processIncoming(msg) //处理消息
		// if err != nil {
		// 	if err != errDisconnect {
		// 		glog.Errorf("(%s) Error processing %s: %v", c.getcid(), msg.Name(), err)
		// 	} else {
		// 		return
		// 	}
		// }

		// // 7. We should commit the bytes in the buffer so we can move on
		// _, err = c.in.ReadCommit(total) //这个时候才移动in的cursor，之前只是读取数据不移动cursor
		// if err != nil {
		// 	if err != io.EOF {
		// 		glog.Errorf("(%s) Error committing %d read bytes: %v", c.getcid(), total, err)
		// 	}
		// 	return
		// }

		// // 7. Check to see if done is closed, if so, exit
		// if c.isDone() && c.in.Len() == 0 {
		// 	return
		// }

		// n, err := nc.Read(b)
		// if err != nil {
		// 	c.closeConnection()
		// 	return
		// }
		// //wbt
		// if c.kicked {
		// 	c.closeConnection()
		// 	return
		// }

		// Grab for updates for last activity.
		last := time.Now()

		// Clear inbound stats cache
		c.cache.inMsgs = 0
		c.cache.inBytes = 0
		c.cache.subs = 0 //sub记录processSub和unsubscribe被调用，用来指示下面记录当前client是活动的最后时间(last)

		// 5. Process the read message
		err = c.processIncoming(msg) //处理消息
		if err != nil {
			if err != errDisconnect {
				c.Errorf("Error processing %s: %v", msg.Name(), err)
				c.closeConnection()
			} else {
				c.Noticef("Error processing2 %s: %v", msg.Name(), err)
				c.closeConnection()
				return
			}
		}

		// 6. We should commit the bytes in the buffer so we can move on
		_, err = br.Discard(total) //这个时候才移动in的cursor，之前只是读取数据不移动cursor
		if err != nil {
			// if err != io.EOF {
			// 	glog.Errorf("(%s) Error committing %d read bytes: %v", c.getcid(), total, err)
			// }
			c.closeConnection()
			return
		}

		c.cache.inBytes = n
		// if err := c.parse(b[:n]); err != nil { //解析命令并执行
		// 	// handled inline
		// 	if err != ErrMaxPayload && err != ErrAuthorization {
		// 		c.Errorf("Error reading from client: %s", err.Error())
		// 		// c.sendErr("Parser Error")
		// 		c.closeConnection()
		// 	}
		// 	return
		// }
		// Updates stats for client and server that were collected
		// from parsing through the buffer.
		// 统计收到的消息总数和字节总数。在上面的parse中会收集最新收到的消息数和字节数
		atomic.AddInt64(&c.inMsgs, int64(c.cache.inMsgs))
		atomic.AddInt64(&c.inBytes, int64(c.cache.inBytes))
		atomic.AddInt64(&s.inMsgs, int64(c.cache.inMsgs))
		atomic.AddInt64(&s.inBytes, int64(c.cache.inBytes))

		// Check pending clients for flush.
		for cp := range c.pcd { //遍历缓冲发送队列，发送数据
			// Flush those in the set
			cp.mu.Lock()
			if cp.nc != nil {
				// Gather the flush calls that happened before now.
				// This is a signal into us about dynamic buffer allocation tuning.
				wfc := cp.wfc
				cp.wfc = 0
				// c.Noticef("flush pcd: %v", cp)
				//SetWriteDeadline是设置tcp发送数据的允许的超时时间，当超时了则会中断写入，可能造成数据只发了一部分
				//此时Flush()会返回错误，然后下面就关闭连接
				cp.nc.SetWriteDeadline(time.Now().Add(opts.WriteDeadline))
				err := cp.bw.Flush() //真正发包
				cp.nc.SetWriteDeadline(time.Time{})
				if err != nil {
					c.Debugf("Error flushing: %v", err)
					cp.mu.Unlock()
					cp.closeConnection()
					cp.mu.Lock()
				} else {
					// Update outbound last activity.
					cp.last = last
					// Check if we should tune the buffer.
					sz := cp.bw.Available()
					// Check for expansion opportunity.
					if wfc > 2 && sz <= maxBufSize/2 { //当缓存大小不够的情况大于2次且可写缓存没有超过最大缓存限制的一半时放大缓存
						cp.bw = bufio.NewWriterSize(cp.nc, sz*2)
					}
					// Check for shrinking opportunity.
					if wfc == 0 && sz >= minBufSize*2 { //当缓存太大时缩小一半
						cp.bw = bufio.NewWriterSize(cp.nc, sz/2)
					}
				}
			}
			cp.mu.Unlock()
			delete(c.pcd, cp) //包已经发出可以在等待队列中移除了
		}
		// Check to see if we got closed, e.g. slow consumer
		c.mu.Lock()
		nc := c.nc
		// Activity based on interest changes or data/msgs.
		if c.cache.inMsgs > 0 || c.cache.subs > 0 {
			c.last = last
		}
		c.mu.Unlock()
		if nc == nil || c.isDone() {
			c.Noticef("c is done")
			return
		}
		// Update buffer size as/if needed.

		// // Grow
		// if n == len(b) && len(b) < maxBufSize {
		// 	b = make([]byte, len(b)*2)
		// }

		// // Shrink, for now don't accelerate, ping/pong will eventually sort it out.
		// if n < len(b)/2 && len(b) > minBufSize {
		// 	b = make([]byte, len(b)/2)
		// }
	}
}

type (
	OnCompleteFunc func(msg, ack message.Message, err error) error
	// OnPublishFunc  func(msg *message.PublishMessage) error
)

func (c *client) isDone() bool {
	select {
	case <-c.done:
		return true

	default:
	}

	return false
}

func (c *client) getcid() string {
	if c.sess != nil {
		return fmt.Sprintf("%d/%s", c.cid, c.sess.ID())
	} else {
		return fmt.Sprintf("%d", c.cid)
	}
}

func (c *client) publishToClient(caller *client, msg *message.PublishMessage, qos byte, onComplete OnCompleteFunc) error {
	//glog.Debugf("client/publish: Publishing %s", msg)
	// c.Noticef("write publishToClient:%v", msg)
	_, err := caller.deliverWriteMessage(c, msg)
	if err != nil {
		return fmt.Errorf("(%s) Error sending %s message: %v", c.getcid(), msg.Name(), err)
	}

	switch msg.QoS() {
	case message.QosAtMostOnce:
		if onComplete != nil {
			return onComplete(msg, nil, nil)
		}

		return nil

	case message.QosAtLeastOnce:
		// return c.sess.Pub1ack.Wait(msg, onComplete)
		return c.sess.Pub1ack.WaitPub(msg, qos, onComplete)

	case message.QosExactlyOnce:
		// return c.sess.Pub2out.Wait(msg, onComplete)
		return c.sess.Pub2out.WaitPub(msg, qos, onComplete)
	}

	return nil
}

// func (c *client) subscribe(msg *message.SubscribeMessage, onComplete OnCompleteFunc, onPublish OnPublishFunc) error {
// 	if onPublish == nil {
// 		return fmt.Errorf("onPublish function is nil. No need to subscribe.")
// 	}

// 	_, err := c.writeMessage(msg)
// 	if err != nil {
// 		return fmt.Errorf("(%s) Error sending %s message: %v", c.getcid(), msg.Name(), err)
// 	}

// 	var onc OnCompleteFunc = func(msg, ack message.Message, err error) error {
// 		onComplete := onComplete
// 		onPublish := onPublish

// 		if err != nil {
// 			if onComplete != nil {
// 				return onComplete(msg, ack, err)
// 			}
// 			return err
// 		}

// 		sub, ok := msg.(*message.SubscribeMessage)
// 		if !ok {
// 			if onComplete != nil {
// 				return onComplete(msg, ack, fmt.Errorf("Invalid SubscribeMessage received"))
// 			}
// 			return nil
// 		}

// 		suback, ok := ack.(*message.SubackMessage)
// 		if !ok {
// 			if onComplete != nil {
// 				return onComplete(msg, ack, fmt.Errorf("Invalid SubackMessage received"))
// 			}
// 			return nil
// 		}

// 		if sub.PacketId() != suback.PacketId() {
// 			if onComplete != nil {
// 				return onComplete(msg, ack, fmt.Errorf("Sub and Suback packet ID not the same. %d != %d.", sub.PacketId(), suback.PacketId()))
// 			}
// 			return nil
// 		}

// 		retcodes := suback.ReturnCodes()
// 		topics := sub.Topics()

// 		if len(topics) != len(retcodes) {
// 			if onComplete != nil {
// 				return onComplete(msg, ack, fmt.Errorf("Incorrect number of return codes received. Expecting %d, got %d.", len(topics), len(retcodes)))
// 			}
// 			return nil
// 		}

// 		var err2 error = nil

// 		for i, t := range topics {
// 			qos := retcodes[i]

// 			if qos == message.QosFailure {
// 				err2 = fmt.Errorf("Failed to subscribe to '%s'\n%v", string(t), err2)
// 			} else {
// 				c.sess.AddTopic(string(t), qos)
// 				_, err := c.topicsMgr.Subscribe(t, qos, &onPublish)
// 				if err != nil {
// 					err2 = fmt.Errorf("Failed to subscribe to '%s' (%v)\n%v", string(t), err, err2)
// 				}
// 			}
// 		}

// 		if onComplete != nil {
// 			return onComplete(msg, ack, err2)
// 		}

// 		return err2
// 	}

// 	return c.sess.Suback.Wait(msg, onc)
// }

func (c *client) unsubscribe2(msg *message.UnsubscribeMessage, onComplete OnCompleteFunc) error {
	_, err := c.writeMessage(msg)
	if err != nil {
		return fmt.Errorf("(%s) Error sending %s message: %v", c.getcid(), msg.Name(), err)
	}

	var onc OnCompleteFunc = func(msg, ack message.Message, err error) error {
		onComplete := onComplete

		if err != nil {
			if onComplete != nil {
				return onComplete(msg, ack, err)
			}
			return err
		}

		unsub, ok := msg.(*message.UnsubscribeMessage)
		if !ok {
			if onComplete != nil {
				return onComplete(msg, ack, fmt.Errorf("Invalid UnsubscribeMessage received"))
			}
			return nil
		}

		unsuback, ok := ack.(*message.UnsubackMessage)
		if !ok {
			if onComplete != nil {
				return onComplete(msg, ack, fmt.Errorf("Invalid UnsubackMessage received"))
			}
			return nil
		}

		if unsub.PacketId() != unsuback.PacketId() {
			if onComplete != nil {
				return onComplete(msg, ack, fmt.Errorf("Unsub and Unsuback packet ID not the same. %d != %d.", unsub.PacketId(), unsuback.PacketId()))
			}
			return nil
		}

		var err2 error = nil

		for _, tb := range unsub.Topics() {
			// Remove all subscribers, which basically it's just c client, since
			// each client has it's own topic tree.
			err := c.topicsMgr.Unsubscribe(tb, nil)
			if err != nil {
				err2 = fmt.Errorf("%v\n%v", err2, err)
			}

			c.sess.RemoveTopic(string(tb))
		}

		if onComplete != nil {
			return onComplete(msg, ack, err2)
		}

		return err2
	}

	return c.sess.Unsuback.Wait(msg, onc)
}
func (c *client) writeMessage(msg message.Message) (int, error) {
	return c.writeMessageWithFlush(c, msg, true)
}
func (c *client) deliverWriteMessage(sub *client, msg message.Message) (int, error) {
	return c.writeMessageWithFlush(sub, msg, false)
}

func (c *client) writeMessageWithFlush(sub *client, msg message.Message, flush bool) (int, error) {
	var (
		l int = msg.Len()
		// m, n int
		err error
		buf []byte
	)

	// if sub.client == nil {
	// 	return 0, false
	// }
	// client := sub.client
	client := sub
	client.mu.Lock()
	if client.nc == nil {
		client.mu.Unlock()
		return 0, errors.New("client is null")
	}

	// Update statistics

	// The msg includes the CR_LF, so pull back out for accounting.
	msgSize := int64(l)

	// No atomic needed since accessed under client lock.
	// Monitor is reading those also under client's lock.
	client.outMsgs++
	client.outBytes += msgSize

	atomic.AddInt64(&c.srv.outMsgs, 1)
	atomic.AddInt64(&c.srv.outBytes, msgSize)

	// Check to see if our writes will cause a flush
	// in the underlying bufio. If so limit time we
	// will wait for flush to complete.

	deadlineSet := false
	if client.bw.Available() < l {
		client.wfc++ //如果缓存不够大则加一次计数，当wfc>2时，会扩展缓存大小
		client.nc.SetWriteDeadline(time.Now().Add(client.srv.getOpts().WriteDeadline))
		deadlineSet = true
	}

	buf = make([]byte, l)
	n, err := msg.Encode(buf[0:])
	if err != nil {
		c.Errorf("Encode:%d,%v", n, err)
		client.mu.Unlock()
		return 0, err
	}

	// c.Noticef("write msg: %d, %d", n, len(buf))
	// Deliver to the client.
	buf = buf[0:n]
	_, err = client.bw.Write(buf)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok {
			c.Errorf("Write2: net error:%v, %v", ne, ne.Temporary())
			// if !ne.Temporary() {
			// 	client.closeConnection()
			// }
		} else {
			c.Errorf("Write1:%v, %v", err, client.nc == nil)
		}
		// debug.PrintStack()
		goto writeErr
	}
	if flush {
		client.bw.Flush()
	}

	// TODO(dlc) - Do we need c or can we just call always?
	if deadlineSet {
		client.nc.SetWriteDeadline(time.Time{})
	}

	client.mu.Unlock()
	if !flush {
		c.pcd[client] = needFlush
	}
	return l, nil

writeErr:
	if deadlineSet {
		client.nc.SetWriteDeadline(time.Time{})
	}
	client.mu.Unlock()

	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		atomic.AddInt64(&client.srv.slowConsumers, 1)
		client.Noticef("Slow Consumer Detected")
		client.closeConnection()
	} else {
		c.Debugf("Error writing msg: %v", err)
	}
	// Honor at most once semantic:
	// treat message that we attempted to send as actually sent
	// and don't let a higher-level code an attempt to resend it.
	return 0, nil
}

func (c *client) processIncoming(msg message.Message) error {
	//wbt: 这里面需要锁c.mu.Lock()

	var err error = nil

	// c.Noticef("processIncoming:%v", msg)

	switch msg := msg.(type) {
	case *message.PublishMessage:
		// For PUBLISH message, we should figure out what QoS it is and process accordingly
		// If QoS == 0, we should just take the next step, no ack required
		// If QoS == 1, we should send back PUBACK, then take the next step
		// If QoS == 2, we need to put it in the ack queue, send back PUBREC
		err = c.processPublish(msg)

	case *message.PubackMessage:
		// For PUBACK message, it means QoS 1, we should send to ack queue
		c.sess.Pub1ack.Ack(msg)
		c.processAcked(c.sess.Pub1ack)

	case *message.PubrecMessage:
		// For PUBREC message, it means QoS 2, we should send to ack queue, and send back PUBREL
		if err = c.sess.Pub2out.Ack(msg); err != nil {
			break
		}

		resp := message.NewPubrelMessage()
		resp.SetPacketId(msg.PacketId())
		_, err = c.writeMessage(resp)

	case *message.PubrelMessage:
		// For PUBREL message, it means QoS 2, we should send to ack queue, and send back PUBCOMP
		if err = c.sess.Pub2in.Ack(msg); err != nil {
			break
		}

		c.processAcked(c.sess.Pub2in)

		resp := message.NewPubcompMessage()
		resp.SetPacketId(msg.PacketId())
		_, err = c.writeMessage(resp)

	case *message.PubcompMessage:
		// For PUBCOMP message, it means QoS 2, we should send to ack queue
		if err = c.sess.Pub2out.Ack(msg); err != nil {
			break
		}

		c.processAcked(c.sess.Pub2out)

	case *message.SubscribeMessage:
		// For SUBSCRIBE message, we should add subscriber, then send back SUBACK
		return c.processSubscribe(msg)

	case *message.SubackMessage:
		// For SUBACK message, we should send to ack queue
		c.sess.Suback.Ack(msg)
		c.processAcked(c.sess.Suback)

	case *message.UnsubscribeMessage:
		// For UNSUBSCRIBE message, we should remove subscriber, then send back UNSUBACK
		return c.processUnsubscribe(msg)

	case *message.UnsubackMessage:
		// For UNSUBACK message, we should send to ack queue
		c.sess.Unsuback.Ack(msg)
		c.processAcked(c.sess.Unsuback)

	case *message.PingreqMessage:
		c.Noticef("processIncoming:%v", msg)
		// For PINGREQ message, we should send back PINGRESP
		resp := message.NewPingrespMessage()
		_, err = c.writeMessage(resp)

	case *message.PingrespMessage:
		c.sess.Pingack.Ack(msg)
		c.processAcked(c.sess.Pingack)

	case *message.DisconnectMessage:
		// For DISCONNECT message, we should quit
		c.sess.Cmsg.SetWillFlag(false)
		return errDisconnect

	default:
		return fmt.Errorf("(%s) invalid message type %s.", c.getcid(), msg.Name())
	}

	if err != nil {
		glog.Debugf("(%s) Error processing acked message: %v", c.getcid(), err)
	}

	return err
}

func (c *client) processAcked(ackq *sessions.Ackqueue) {
	// c.Noticef("processAcked1")
	for _, ackmsg := range ackq.Acked() {
		// c.Noticef("processAcked2")

		// Let's get the messages from the saved message byte slices.
		msg, err := ackmsg.Mtype.New()
		if err != nil {
			glog.Errorf("process/processAcked: Unable to creating new %s message: %v", ackmsg.Mtype, err)
			continue
		}

		if _, err := msg.Decode(ackmsg.Msgbuf); err != nil {
			glog.Errorf("process/processAcked: Unable to decode %s message: %v", ackmsg.Mtype, err)
			continue
		}

		ack, err := ackmsg.State.New()
		if err != nil {
			glog.Errorf("process/processAcked: Unable to creating new %s message: %v", ackmsg.State, err)
			continue
		}

		if _, err := ack.Decode(ackmsg.Ackbuf); err != nil {
			glog.Errorf("process/processAcked: Unable to decode %s message: %v", ackmsg.State, err)
			continue
		}

		//glog.Debugf("(%s) Processing acked message: %v", c.getcid(), ack)

		// - PUBACK if it's QoS 1 message. This is on the client side.
		// - PUBREL if it's QoS 2 message. This is on the server side.
		// - PUBCOMP if it's QoS 2 message. This is on the client side.
		// - SUBACK if it's a subscribe message. This is on the client side.
		// - UNSUBACK if it's a unsubscribe message. This is on the client side.
		// c.Noticef("processAcked3:%v", ackmsg.State)

		switch ackmsg.State {
		case message.PUBREL:
			// If ack is PUBREL, that means the QoS 2 message sent by a remote client is
			// releassed, so let's publish it to other subscribers.
			// c.Noticef("PUBREL onPublish:%v", msg.Len())
			if err = c.onPublish(msg.(*message.PublishMessage)); err != nil {
				glog.Errorf("(%s) Error processing ack'ed %s message: %v", c.getcid(), ackmsg.Mtype, err)
			}

		case message.PUBACK, message.PUBCOMP, message.SUBACK, message.UNSUBACK, message.PINGRESP:
			glog.Debugf("process/processAcked: %s", ack)
			// If ack is PUBACK, that means the QoS 1 message sent by c client got
			// ack'ed. There's nothing to do other than calling onComplete() below.

			// If ack is PUBCOMP, that means the QoS 2 message sent by c client got
			// ack'ed. There's nothing to do other than calling onComplete() below.

			// If ack is SUBACK, that means the SUBSCRIBE message sent by c client
			// got ack'ed. There's nothing to do other than calling onComplete() below.

			// If ack is UNSUBACK, that means the SUBSCRIBE message sent by c client
			// got ack'ed. There's nothing to do other than calling onComplete() below.

			// If ack is PINGRESP, that means the PINGREQ message sent by c client
			// got ack'ed. There's nothing to do other than calling onComplete() below.

			err = nil

		default:
			glog.Errorf("(%s) Invalid ack message type %s.", c.getcid(), ackmsg.State)
			continue
		}

		// Call the registered onComplete function
		if ackmsg.OnComplete != nil {
			onComplete, ok := ackmsg.OnComplete.(OnCompleteFunc)
			if !ok {
				glog.Errorf("process/processAcked: Error type asserting onComplete function: %v", reflect.TypeOf(ackmsg.OnComplete))
			} else if onComplete != nil {
				if err := onComplete(msg, ack, nil); err != nil {
					glog.Errorf("process/processAcked: Error running onComplete(): %v", err)
				}
			}
		}
	}
}

// For PUBLISH message, we should figure out what QoS it is and process accordingly
// If QoS == 0, we should just take the next step, no ack required
// If QoS == 1, we should send back PUBACK, then take the next step
// If QoS == 2, we need to put it in the ack queue, send back PUBREC
func (c *client) processPublish(msg *message.PublishMessage) error {
	switch msg.QoS() {
	case message.QosExactlyOnce:
		c.sess.Pub2in.Wait(msg, nil)

		resp := message.NewPubrecMessage()
		resp.SetPacketId(msg.PacketId())

		_, err := c.writeMessage(resp)
		return err

	case message.QosAtLeastOnce:
		resp := message.NewPubackMessage()
		resp.SetPacketId(msg.PacketId())

		if _, err := c.writeMessage(resp); err != nil {
			return err
		}

		return c.onPublish(msg)

	case message.QosAtMostOnce:
		return c.onPublish(msg)
	}

	return fmt.Errorf("(%s) invalid message QoS %d.", c.getcid(), msg.QoS())
}

// For SUBSCRIBE message, we should add subscriber, then send back SUBACK
func (c *client) processSubscribe(msg *message.SubscribeMessage) error {
	resp := message.NewSubackMessage()
	resp.SetPacketId(msg.PacketId())

	// Subscribe to the different topics
	var retcodes []byte

	topics := msg.Topics()
	qos := msg.Qos()

	c.rmsgs = c.rmsgs[0:0]

	for i, t := range topics { //一次订阅可以订阅多个主题
		rqos, err := c.topicsMgr.Subscribe(t, qos[i], c) //&c.onpub)
		if err != nil {
			return err
		}
		c.sess.AddTopic(string(t), qos[i])

		retcodes = append(retcodes, rqos)

		// yeah I am not checking errors here. If there's an error we don't want the
		// subscription to stop, just let it go.
		c.topicsMgr.Retained(t, &c.rmsgs) //找到topic中的最后一条保留的publish消息复制到c.rmsgs中（用来重发）
		glog.Debugf("(%s) topic = %s, retained count = %d", c.getcid(), string(t), len(c.rmsgs))
	}

	if err := resp.AddReturnCodes(retcodes); err != nil {
		return err
	}

	if _, err := c.writeMessage(resp); err != nil {
		return err
	}

	for _, rm := range c.rmsgs { //重发保留publish消息
		if err := c.publishToClient(c, rm, rm.QoS(), nil); err != nil {
			glog.Errorf("client/processSubscribe: Error publishing retained message: %v", err)
			return err
		}
	}
	if len(c.rmsgs) > 0 {
		c.bw.Flush()
	}

	return nil
}

// For UNSUBSCRIBE message, we should remove the subscriber, and send back UNSUBACK
func (c *client) processUnsubscribe(msg *message.UnsubscribeMessage) error {
	topics := msg.Topics()

	for _, t := range topics {
		c.topicsMgr.Unsubscribe(t, c) //&c.onpub)
		c.sess.RemoveTopic(string(t))
	}

	resp := message.NewUnsubackMessage()
	resp.SetPacketId(msg.PacketId())

	_, err := c.writeMessage(resp)
	return err
}

// onPublish() is called when the server receives a PUBLISH message AND have completed
// the ack cycle. This method will get the list of subscribers based on the publish
// topic, and publishes the message to the list of subscribers.
func (c *client) onPublish(msg *message.PublishMessage) error {
	if msg.Retain() {
		if err := c.topicsMgr.Retain(msg); err != nil {
			glog.Errorf("(%s) Error retaining message: %v", c.getcid(), err)
		}
	}

	//wbt: 不管订阅者的qos和msg.qos的值是多少，都得发给订阅者。
	//只不过发送时要按照两者qos小的那个规则来发送。
	//所以发送给客户端时要修改qos。
	//原版如果msg.qos大于sub.qos，那么就为会发给客户端，这是错误的。
	err := c.topicsMgr.Subscribers(msg.Topic(), msg.QoS(), &c.subs2, &c.qoss)
	if err != nil {
		glog.Errorf("(%s) Error retrieving subscribers list: %v", c.getcid(), err)
		return err
	}

	msg.SetRetain(false)

	//glog.Debugf("(%s) Publishing to topic %q and %d subscribers", c.getcid(), string(msg.Topic()), len(c.subs))
	if len(c.subs2) > 0 {
		for i, s := range c.subs2 { //遍历所有订阅者发送消息
			if s != nil {
				// c.Noticef("onPublish: %v", s)
				fn, ok := s.(*client) //s.(*OnPublishFunc)
				if !ok {
					glog.Errorf("Invalid onPublish Function")
					return fmt.Errorf("Invalid onPublish Function")
				} else {
					// (*fn)(msg)
					//取小的qos
					qos := c.qoss[i]
					if qos > msg.QoS() {
						qos = msg.QoS()
					}
					fn.publishToClient(c, msg, qos, nil)
					// c.deliverWriteMessage(fn, msg)
				}
			}
		}
		c.subs2 = c.subs2[0:0]
	}

	return nil
}

func (c *client) traceMsg(msg []byte) {
	if !c.trace {
		return
	}
	// FIXME(dlc), allow limits to printable payload
	c.Tracef("->> MSG_PAYLOAD: [%s]", string(msg[:len(msg)-LEN_CR_LF]))
}

func (c *client) traceInOp(op string, arg []byte) {
	c.traceOp("->> %s", op, arg)
}

func (c *client) traceOutOp(op string, arg []byte) {
	c.traceOp("<<- %s", op, arg)
}

func (c *client) traceOp(format, op string, arg []byte) {
	if !c.trace {
		return
	}

	opa := []interface{}{}
	if op != "" {
		opa = append(opa, op)
	}
	if arg != nil {
		opa = append(opa, string(arg))
	}
	c.Tracef(format, opa)
}

// Process the information messages from Clients and other Routes.
func (c *client) processInfo(arg []byte) error {
	info := Info{}
	if err := json.Unmarshal(arg, &info); err != nil {
		return err
	}
	if c.typ == ROUTER {
		c.processRouteInfo(&info)
	}
	return nil
}

func (c *client) processErr(errStr string) {
	switch c.typ {
	case CLIENT:
		c.Errorf("Client Error %s", errStr)
	case ROUTER:
		c.Errorf("Route Error %s", errStr)
	}
	c.closeConnection()
}

func (c *client) processConnect(arg []byte) error {
	c.traceInOp("CONNECT", arg)

	c.mu.Lock()
	// If we can't stop the timer because the callback is in progress...
	if !c.clearAuthTimer() {
		// wait for it to finish and handle sending the failure back to
		// the client.
		for c.nc != nil {
			c.mu.Unlock()
			time.Sleep(25 * time.Millisecond)
			c.mu.Lock()
		}
		c.mu.Unlock()
		return nil
	}
	c.last = time.Now()
	typ := c.typ
	r := c.route
	srv := c.srv
	// Moved unmarshalling of clients' Options under the lock.
	// The client has already been added to the server map, so it is possible
	// that other routines lookup the client, and access its options under
	// the client's lock, so unmarshalling the options outside of the lock
	// would cause data RACEs.
	if err := json.Unmarshal(arg, &c.opts); err != nil {
		c.mu.Unlock()
		return err
	}
	// Indicate that the CONNECT protocol has been received, and that the
	// server now knows which protocol c client supports.
	c.flags.set(connectReceived)
	// Capture these under lock
	proto := c.opts.Protocol
	verbose := c.opts.Verbose
	lang := c.opts.Lang
	c.mu.Unlock()

	if srv != nil {
		// As soon as c.opts is unmarshalled and if the proto is at
		// least ClientProtoInfo, we need to increment the following counter.
		// This is decremented when client is removed from the server's
		// clients map.
		if proto >= ClientProtoInfo {
			srv.mu.Lock()
			srv.cproto++
			srv.mu.Unlock()
		}

		// Check for Auth
		if ok := srv.checkAuthorization(c); !ok {
			c.authViolation()
			return ErrAuthorization
		}
	}

	// Check client protocol request if it exists.
	if typ == CLIENT && (proto < ClientProtoZero || proto > ClientProtoInfo) {
		c.sendErr(ErrBadClientProtocol.Error())
		c.closeConnection()
		return ErrBadClientProtocol
	} else if typ == ROUTER && lang != "" {
		// Way to detect clients that incorrectly connect to the route listen
		// port. Client provide Lang in the CONNECT protocol while ROUTEs don't.
		c.sendErr(ErrClientConnectedToRoutePort.Error())
		c.closeConnection()
		return ErrClientConnectedToRoutePort
	}

	// Grab connection name of remote route.
	if typ == ROUTER && r != nil {
		c.mu.Lock()
		c.route.remoteID = c.opts.Name
		c.mu.Unlock()
	}

	if verbose {
		c.sendOK()
	}
	return nil
}

func (c *client) authTimeout() {
	c.sendErr(ErrAuthTimeout.Error())
	c.Debugf("Authorization Timeout")
	c.closeConnection()
}

func (c *client) authViolation() {
	if c.srv != nil && c.srv.getOpts().Users != nil {
		c.Errorf("%s - User %q",
			ErrAuthorization.Error(),
			c.opts.Username)
	} else {
		c.Errorf(ErrAuthorization.Error())
	}
	c.sendErr("Authorization Violation")
	c.closeConnection()
}

func (c *client) maxConnExceeded() {
	c.Errorf(ErrTooManyConnections.Error())
	c.sendErr(ErrTooManyConnections.Error())
	c.closeConnection()
}

func (c *client) maxPayloadViolation(sz int, max int64) {
	c.Errorf("%s: %d vs %d", ErrMaxPayload.Error(), sz, max)
	c.sendErr("Maximum Payload Violation")
	c.closeConnection()
}

// Assume the lock is held upon entry.
func (c *client) sendProto(info []byte, doFlush bool) error {
	var err error
	if c.bw != nil && c.nc != nil {
		deadlineSet := false
		if doFlush || c.bw.Available() < len(info) {
			c.nc.SetWriteDeadline(time.Now().Add(c.srv.getOpts().WriteDeadline))
			deadlineSet = true
		}
		_, err = c.bw.Write(info)
		if err == nil && doFlush {
			err = c.bw.Flush()
		}
		if deadlineSet {
			c.nc.SetWriteDeadline(time.Time{})
		}
	}
	return err
}

// Assume the lock is held upon entry.
func (c *client) sendInfo(info []byte) {
	c.sendProto(info, true)
}

func (c *client) sendErr(err string) {
	// c.mu.Lock()
	// c.traceOutOp("-ERR", []byte(err))
	// c.sendProto([]byte(fmt.Sprintf("-ERR '%s'\r\n", err)), true)
	// c.mu.Unlock()
}

func (c *client) sendOK() {
	c.mu.Lock()
	c.traceOutOp("OK", nil)
	// Can not autoflush c one, needs to be async.
	c.sendProto([]byte("+OK\r\n"), false)
	c.pcd[c] = needFlush
	c.mu.Unlock()
}

func (c *client) processPing() {
	c.mu.Lock()
	c.traceInOp("PING", nil)
	if c.nc == nil {
		c.mu.Unlock()
		return
	}
	c.traceOutOp("PONG", nil)
	if err := c.sendProto([]byte("PONG\r\n"), true); err != nil {
		c.clearConnection()
		c.Debugf("Error on Flush, error %s", err.Error())
		c.mu.Unlock()
		return
	}
	// The CONNECT should have been received, but make sure it
	// is so before proceeding
	if !c.flags.isSet(connectReceived) {
		c.mu.Unlock()
		return
	}
	// If we are here, the CONNECT has been received so we know
	// if c client supports async INFO or not.
	var (
		checkClusterChange bool
		srv                = c.srv
	)
	// For older clients, just flip the firstPongSent flag if not already
	// set and we are done.
	if c.opts.Protocol < ClientProtoInfo || srv == nil {
		c.flags.setIfNotSet(firstPongSent)
	} else {
		// This is a client that supports async INFO protocols.
		// If c is the first PING (so firstPongSent is not set yet),
		// we will need to check if there was a change in cluster topology.
		checkClusterChange = !c.flags.isSet(firstPongSent)
	}
	c.mu.Unlock()

	if checkClusterChange {
		srv.mu.Lock()
		c.mu.Lock()
		// Now that we are under both locks, we can flip the flag.
		// This prevents sendAsyncInfoToClients() and and code here
		// to send a double INFO protocol.
		c.flags.set(firstPongSent)
		// If there was a cluster update since c client was created,
		// send an updated INFO protocol now.
		if srv.lastCURLsUpdate >= c.start.UnixNano() {
			c.sendInfo(srv.infoJSON)
		}
		c.mu.Unlock()
		srv.mu.Unlock()
	}
}

func (c *client) processPong() {
	c.traceInOp("PONG", nil)
	c.mu.Lock()
	c.pout = 0
	c.mu.Unlock()
}

func (c *client) processMsgArgs(arg []byte) error {
	if c.trace {
		c.traceInOp("MSG", arg)
	}

	// Unroll splitArgs to avoid runtime/heap issues
	a := [MAX_MSG_ARGS][]byte{}
	args := a[:0]
	start := -1
	for i, b := range arg {
		switch b {
		case ' ', '\t', '\r', '\n':
			if start >= 0 {
				args = append(args, arg[start:i])
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		args = append(args, arg[start:])
	}

	switch len(args) {
	case 3:
		c.pa.reply = nil
		c.pa.szb = args[2]
		c.pa.size = parseSize(args[2])
	case 4:
		c.pa.reply = args[2]
		c.pa.szb = args[3]
		c.pa.size = parseSize(args[3])
	default:
		return fmt.Errorf("processMsgArgs Parse Error: '%s'", arg)
	}
	if c.pa.size < 0 {
		return fmt.Errorf("processMsgArgs Bad or Missing Size: '%s'", arg)
	}

	// Common ones processed after check for arg length
	c.pa.subject = args[0]
	c.pa.sid = args[1]

	return nil
}

func (c *client) processPub(arg []byte) error {
	if c.trace {
		c.traceInOp("PUB", arg)
	}

	// Unroll splitArgs to avoid runtime/heap issues
	a := [MAX_PUB_ARGS][]byte{}
	args := a[:0]
	start := -1
	for i, b := range arg {
		switch b {
		case ' ', '\t':
			if start >= 0 {
				args = append(args, arg[start:i])
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		args = append(args, arg[start:])
	}

	switch len(args) {
	case 2:
		c.pa.subject = args[0]
		c.pa.reply = nil
		c.pa.size = parseSize(args[1])
		c.pa.szb = args[1]
	case 3:
		c.pa.subject = args[0]
		c.pa.reply = args[1]
		c.pa.size = parseSize(args[2])
		c.pa.szb = args[2]
	default:
		return fmt.Errorf("processPub Parse Error: '%s'", arg)
	}
	if c.pa.size < 0 {
		return fmt.Errorf("processPub Bad or Missing Size: '%s'", arg)
	}
	maxPayload := atomic.LoadInt64(&c.mpay)
	if maxPayload > 0 && int64(c.pa.size) > maxPayload {
		c.maxPayloadViolation(c.pa.size, maxPayload)
		return ErrMaxPayload
	}

	if c.opts.Pedantic && !IsValidLiteralSubject(string(c.pa.subject)) {
		c.sendErr("Invalid Subject")
	}
	return nil
}

func splitArg(arg []byte) [][]byte {
	a := [MAX_MSG_ARGS][]byte{}
	args := a[:0]
	start := -1
	for i, b := range arg {
		switch b {
		case ' ', '\t', '\r', '\n':
			if start >= 0 {
				args = append(args, arg[start:i])
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		args = append(args, arg[start:])
	}
	return args
}

func (c *client) processSub(argo []byte) (err error) {
	c.traceInOp("SUB", argo)

	// Indicate activity.
	c.cache.subs++

	// Copy so we do not reference a potentially large buffer
	arg := make([]byte, len(argo))
	copy(arg, argo)
	args := splitArg(arg)
	sub := &subscription{client: c}
	switch len(args) {
	case 2:
		sub.subject = args[0]
		sub.queue = nil
		sub.sid = args[1]
	case 3:
		sub.subject = args[0]
		sub.queue = args[1]
		sub.sid = args[2]
	default:
		return fmt.Errorf("processSub Parse Error: '%s'", arg)
	}

	shouldForward := false

	c.mu.Lock()
	if c.nc == nil {
		c.mu.Unlock()
		return nil
	}

	// Check permissions if applicable.
	if !c.canSubscribe(sub.subject) {
		c.mu.Unlock()
		c.sendErr(fmt.Sprintf("Permissions Violation for Subscription to %q", sub.subject))
		c.Errorf("Subscription Violation - User %q, Subject %q, SID %s",
			c.opts.Username, sub.subject, sub.sid)
		return nil
	}

	// We can have two SUB protocols coming from a route due to some
	// race conditions. We should make sure that we process only one.
	sid := string(sub.sid)
	if c.subs[sid] == nil {
		c.subs[sid] = sub
		if c.srv != nil {
			err = c.srv.sl.Insert(sub)
			if err != nil {
				delete(c.subs, sid)
			} else {
				shouldForward = c.typ != ROUTER
			}
		}
	}
	c.mu.Unlock()
	if err != nil {
		c.sendErr("Invalid Subject")
		return nil
	} else if c.opts.Verbose {
		c.sendOK()
	}
	if shouldForward {
		c.srv.broadcastSubscribe(sub)
	}

	return nil
}

// canSubscribe determines if the client is authorized to subscribe to the
// given subject. Assumes caller is holding lock.
func (c *client) canSubscribe(sub []byte) bool {
	if c.perms == nil {
		return true
	}
	return len(c.perms.sub.Match(string(sub)).psubs) > 0
}

func (c *client) unsubscribe(sub *subscription) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sub.max > 0 && sub.nm < sub.max {
		c.Debugf(
			"Deferring actual UNSUB(%s): %d max, %d received\n",
			string(sub.subject), sub.max, sub.nm)
		return
	}
	c.traceOp("<-> %s", "DELSUB", sub.sid)
	delete(c.subs, string(sub.sid))
	if c.srv != nil {
		c.srv.sl.Remove(sub)
	}
}

func (c *client) processUnsub(arg []byte) error {
	c.traceInOp("UNSUB", arg)
	args := splitArg(arg)
	var sid []byte
	max := -1

	switch len(args) {
	case 1:
		sid = args[0]
	case 2:
		sid = args[0]
		max = parseSize(args[1]) //收到几条消息后自动取消订阅
	default:
		return fmt.Errorf("processUnsub Parse Error: '%s'", arg)
	}

	// Indicate activity.
	c.cache.subs += 1

	var sub *subscription

	unsub := false
	shouldForward := false
	ok := false

	c.mu.Lock()
	if sub, ok = c.subs[string(sid)]; ok {
		if max > 0 {
			sub.max = int64(max)
		} else {
			// Clear it here to override
			sub.max = 0
		}
		unsub = true
		shouldForward = c.typ != ROUTER && c.srv != nil
	}
	c.mu.Unlock()

	if unsub {
		c.unsubscribe(sub)
	}
	if shouldForward {
		c.srv.broadcastUnSubscribe(sub)
	}
	if c.opts.Verbose {
		c.sendOK()
	}

	return nil
}

func (c *client) msgHeader(mh []byte, sub *subscription) []byte {
	mh = append(mh, sub.sid...)
	mh = append(mh, ' ')
	if c.pa.reply != nil {
		mh = append(mh, c.pa.reply...)
		mh = append(mh, ' ')
	}
	mh = append(mh, c.pa.szb...)
	mh = append(mh, "\r\n"...)
	return mh
}

// Used to treat maps as efficient set
var needFlush = struct{}{}
var routeSeen = struct{}{}

func (c *client) deliverMsg(sub *subscription, mh, msg []byte) bool {
	if sub.client == nil {
		return false
	}
	client := sub.client
	client.mu.Lock()
	sub.nm++
	// Check if we should auto-unsubscribe.
	if sub.max > 0 { //处理自动取消订阅
		// For routing..
		shouldForward := client.typ != ROUTER && client.srv != nil
		// If we are at the exact number, unsubscribe but
		// still process the message in hand, otherwise
		// unsubscribe and drop message on the floor.
		if sub.nm == sub.max {
			c.Debugf("Auto-unsubscribe limit of %d reached for sid '%s'\n", sub.max, string(sub.sid))
			// Due to defer, reverse the code order so that execution
			// is consistent with other cases where we unsubscribe.
			if shouldForward { //广播UnSubscribe给集群
				defer client.srv.broadcastUnSubscribe(sub)
			}
			defer client.unsubscribe(sub)
		} else if sub.nm > sub.max {
			c.Debugf("Auto-unsubscribe limit [%d] exceeded\n", sub.max)
			client.mu.Unlock()
			client.unsubscribe(sub)
			if shouldForward {
				client.srv.broadcastUnSubscribe(sub)
			}
			return false
		}
	}

	if client.nc == nil {
		client.mu.Unlock()
		return false
	}

	// Update statistics

	// The msg includes the CR_LF, so pull back out for accounting.
	msgSize := int64(len(msg) - LEN_CR_LF)

	// No atomic needed since accessed under client lock.
	// Monitor is reading those also under client's lock.
	client.outMsgs++
	client.outBytes += msgSize

	atomic.AddInt64(&c.srv.outMsgs, 1)
	atomic.AddInt64(&c.srv.outBytes, msgSize)

	// Check to see if our writes will cause a flush
	// in the underlying bufio. If so limit time we
	// will wait for flush to complete.

	deadlineSet := false
	if client.bw.Available() < (len(mh) + len(msg)) {
		client.wfc++ //如果缓存不够大则加一次计数，当wfc>2时，会扩展缓存大小
		client.nc.SetWriteDeadline(time.Now().Add(client.srv.getOpts().WriteDeadline))
		deadlineSet = true
	}

	// Deliver to the client.
	_, err := client.bw.Write(mh)
	if err != nil {
		goto writeErr
	}

	_, err = client.bw.Write(msg)
	if err != nil {
		goto writeErr
	}

	if c.trace {
		client.traceOutOp(string(mh[:len(mh)-LEN_CR_LF]), nil)
	}

	// TODO(dlc) - Do we need c or can we just call always?
	if deadlineSet {
		client.nc.SetWriteDeadline(time.Time{})
	}

	client.mu.Unlock()
	c.pcd[client] = needFlush
	return true

writeErr:
	if deadlineSet {
		client.nc.SetWriteDeadline(time.Time{})
	}
	client.mu.Unlock()

	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		atomic.AddInt64(&client.srv.slowConsumers, 1)
		client.Noticef("Slow Consumer Detected")
		client.closeConnection()
	} else {
		c.Debugf("Error writing msg: %v", err)
	}
	// Honor at most once semantic:
	// treat message that we attempted to send as actually sent
	// and don't let a higher-level code an attempt to resend it.
	return true
}

// processMsg is called to process an inbound msg from a client.
func (c *client) processMsg(msg []byte) {
	// Snapshot server.
	srv := c.srv

	// Update statistics
	// The msg includes the CR_LF, so pull back out for accounting.
	c.cache.inMsgs += 1
	c.cache.inBytes += len(msg) - LEN_CR_LF

	if c.trace {
		c.traceMsg(msg)
	}

	// Disallow publish to _SYS.>, these are reserved for internals.
	if c.pa.subject[0] == '_' && len(c.pa.subject) > 4 &&
		c.pa.subject[1] == 'S' && c.pa.subject[2] == 'Y' &&
		c.pa.subject[3] == 'S' && c.pa.subject[4] == '.' {
		c.pubPermissionViolation(c.pa.subject)
		return
	}

	// Check if published subject is allowed if we have permissions in place.
	if c.perms != nil { //权限控制
		allowed, ok := c.perms.pcache[string(c.pa.subject)] //先从缓存中验证
		if ok && !allowed {
			c.pubPermissionViolation(c.pa.subject)
			return
		}
		if !ok {
			r := c.perms.pub.Match(string(c.pa.subject))
			notAllowed := len(r.psubs) == 0
			if notAllowed {
				c.pubPermissionViolation(c.pa.subject)
				c.perms.pcache[string(c.pa.subject)] = false //记录缓存结果
			} else {
				c.perms.pcache[string(c.pa.subject)] = true //记录缓存结果
			}
			// Prune if needed.
			if len(c.perms.pcache) > maxPermCacheSize { //缓存太多，删除前面一半
				// Prune the permissions cache. Keeps us from unbounded growth.
				r := 0
				for subject := range c.perms.pcache {
					delete(c.perms.pcache, subject)
					r++
					if r > pruneSize {
						break
					}
				}
			}
			// Return here to allow the pruning code to run if needed.
			if notAllowed {
				return
			}
		}
	}

	if c.opts.Verbose {
		c.sendOK()
	}

	// Mostly under testing scenarios.
	if srv == nil {
		return
	}

	var r *SublistResult
	var ok bool

	genid := atomic.LoadUint64(&srv.sl.genid) //总sublist自增id

	if genid == c.cache.genid && c.cache.results != nil {
		r, ok = c.cache.results[string(c.pa.subject)]
	} else {
		// reset
		c.cache.results = make(map[string]*SublistResult)
		c.cache.genid = genid
	}

	if !ok {
		subject := string(c.pa.subject)
		r = srv.sl.Match(subject)
		c.cache.results[subject] = r
		if len(c.cache.results) > maxResultCacheSize { //修剪cache
			// Prune the results cache. Keeps us from unbounded growth.
			r := 0
			for subject := range c.cache.results {
				delete(c.cache.results, subject)
				r++
				if r > pruneSize {
					break
				}
			}
		}
	}

	// Check for no interest, short circuit if so.
	if len(r.psubs) == 0 && len(r.qsubs) == 0 { //没人订阅直接返回
		return
	}

	// Check for pedantic and bad subject.
	//pedantic在client时默认为true，在route时默认为false，这应该表示route时不用校验subject的有效性？
	if c.opts.Pedantic && !IsValidLiteralSubject(string(c.pa.subject)) {
		return
	}

	// Scratch buffer..
	msgh := c.msgb[:len(msgHeadProto)]

	// msg header
	msgh = append(msgh, c.pa.subject...)
	msgh = append(msgh, ' ')
	si := len(msgh)

	isRoute := c.typ == ROUTER
	isRouteQsub := false

	// If we are a route and we have a queue subscription, deliver direct
	// since they are sent direct via L2 semantics. If the match is a queue
	// subscription, we will return from here regardless if we find a sub.
	if isRoute { //集群
		isQueue, sub, err := srv.routeSidQueueSubscriber(c.pa.sid)
		if isQueue {
			// We got an invalid QRSID, so stop here
			if err != nil {
				c.Errorf("Unable to deliver messaage: %v", err)
				return
			}
			if sub != nil {
				mh := c.msgHeader(msgh[:si], sub)
				if c.deliverMsg(sub, mh, msg) {
					return
				}
			}
			isRouteQsub = true
			// At c point we know fo sure that it's a queue subscription and
			// we didn't make a delivery attempt, because either a subscriber limit
			// was exceeded or a subscription is already gone.
			// So, let the code below find yet another matching subscription.
			// We are at risk that a message might go back and forth between routes
			// during these attempts, but at the end it shall either be delivered
			// (at most once) or dropped.
		}
	}

	// Don't process normal subscriptions in case of a queue subscription resend.
	// Otherwise, we'd end up with potentially delivering the same message twice.
	if !isRouteQsub { //非集群queue
		// Used to only send normal subscriptions once across a given route.
		var rmap map[string]struct{}

		// Loop over all normal subscriptions that match.

		for _, sub := range r.psubs { //处理正常sub
			// Check if c is a send to a ROUTER, make sure we only send it
			// once. The other side will handle the appropriate re-processing
			// and fan-out. Also enforce 1-Hop semantics, so no routing to another.
			if sub.client.typ == ROUTER { //集群
				// Skip if sourced from a ROUTER and going to another ROUTER.
				// This is 1-Hop semantics for ROUTERs.
				if isRoute {
					continue
				}
				// Check to see if we have already sent it here.
				if rmap == nil {
					rmap = make(map[string]struct{}, srv.numRoutes())
				}
				sub.client.mu.Lock()
				if sub.client.nc == nil || sub.client.route == nil ||
					sub.client.route.remoteID == "" {
					c.Debugf("Bad or Missing ROUTER Identity, not processing msg")
					sub.client.mu.Unlock()
					continue
				}
				if _, ok := rmap[sub.client.route.remoteID]; ok {
					c.Debugf("Ignoring route, already processed")
					sub.client.mu.Unlock()
					continue
				}
				rmap[sub.client.route.remoteID] = routeSeen
				sub.client.mu.Unlock()
			}
			// Normal delivery 正常发送
			mh := c.msgHeader(msgh[:si], sub)
			c.deliverMsg(sub, mh, msg)
		}
	}

	// Now process any queue subs we have if not a route...
	// or if we did not make a delivery attempt yet.
	if isRouteQsub || !isRoute { //处理queue
		// Check to see if we have our own rand yet. Global rand
		// has contention with lots of clients, etc.
		if c.cache.prand == nil { //每个client都有自己的rand
			c.cache.prand = rand.New(rand.NewSource(time.Now().UnixNano()))
		}
		// Process queue subs
		for i := 0; i < len(r.qsubs); i++ {
			qsubs := r.qsubs[i]
			// Find a subscription that is able to deliver c message
			// starting at a random index.
			startIndex := c.cache.prand.Intn(len(qsubs)) //随机取一个qsub来发送
			for i := 0; i < len(qsubs); i++ {            //从startIndex开始循环qsubs所有元素，直到发送成功一次
				index := (startIndex + i) % len(qsubs)
				sub := qsubs[index]
				if sub != nil {
					mh := c.msgHeader(msgh[:si], sub)
					if c.deliverMsg(sub, mh, msg) { //发送成功就退出
						break
					}
				}
			}
		}
	}
}

func (c *client) pubPermissionViolation(subject []byte) {
	c.sendErr(fmt.Sprintf("Permissions Violation for Publish to %q", subject))
	c.Errorf("Publish Violation - User %q, Subject %q", c.opts.Username, subject)
}

func (c *client) processPingTimer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ptmr = nil
	// Check if connection is still opened
	if c.nc == nil {
		return
	}

	c.Debugf("%s Ping Timer", c.typeString())

	// Check for violation
	c.pout++
	if c.pout > c.srv.getOpts().MaxPingsOut {
		c.Debugf("Stale Client Connection - Closing")
		c.sendProto([]byte(fmt.Sprintf("-ERR '%s'\r\n", "Stale Connection")), true)
		c.clearConnection()
		return
	}

	c.traceOutOp("PING", nil)

	// Send PING
	err := c.sendProto([]byte("PING\r\n"), true)
	if err != nil {
		c.Debugf("Error on Client Ping Flush, error %s", err)
		c.clearConnection()
	} else {
		// Reset to fire again if all OK.
		c.setPingTimer()
	}
}

func (c *client) setPingTimer() {
	if c.srv == nil {
		return
	}
	d := c.srv.getOpts().PingInterval
	c.ptmr = time.AfterFunc(d, c.processPingTimer)
}

// Lock should be held
func (c *client) clearPingTimer() {
	if c.ptmr == nil {
		return
	}
	c.ptmr.Stop()
	c.ptmr = nil
}

// Lock should be held
func (c *client) setAuthTimer(d time.Duration) {
	c.atmr = time.AfterFunc(d, func() { c.authTimeout() })
}

// Lock should be held
func (c *client) clearAuthTimer() bool {
	if c.atmr == nil {
		return true
	}
	stopped := c.atmr.Stop()
	c.atmr = nil
	return stopped
}

func (c *client) isAuthTimerSet() bool {
	c.mu.Lock()
	isSet := c.atmr != nil
	c.mu.Unlock()
	return isSet
}

// Lock should be held
func (c *client) clearConnection() {
	if c.nc == nil {
		return
	}
	// With TLS, Close() is sending an alert (that is doing a write).
	// Need to set a deadline otherwise the server could block there
	// if the peer is not reading from socket.
	c.nc.SetWriteDeadline(time.Now().Add(c.srv.getOpts().WriteDeadline))
	if c.bw != nil {
		c.bw.Flush()
	}
	c.nc.Close()
	c.nc.SetWriteDeadline(time.Time{})
}

func (c *client) typeString() string {
	switch c.typ {
	case CLIENT:
		return "Client"
	case ROUTER:
		return "Router"
	}
	return "Unknown Type"
}

// FIXME: The order of closing here causes panic sometimes. For example, if receiver
// calls c, and closes the buffers, somehow it causes buffer.go:476 to panid.
func (c *client) stop() {
	// defer func() {
	// 	// Let's recover from panic
	// 	if r := recover(); r != nil {
	// 		glog.Errorf("(%s) Recovering from panic: %v", c.getcid(), r)
	// 	}
	// }()

	doit := atomic.CompareAndSwapInt64(&c.closed, 0, 1)
	if !doit {
		return
	}

	// Close quit channel, effectively telling all the goroutines it's time to quit
	if c.done != nil {
		glog.Debugf("(%s) closing c.done", c.getcid())
		close(c.done)
	}

	// Close the network connection
	// if c.nc != nil {
	// 	glog.Debugf("(%s) closing c.conn", c.getcid())
	// 	c.nc.Close()
	// }

	// glog.Debugf("(%s) Received %d bytes in %d messages.", c.getcid(), c.inStat.bytes, c.inStat.msgs)
	// glog.Debugf("(%s) Sent %d bytes in %d messages.", c.getcid(), c.outStat.bytes, c.outStat.msgs)

	// Unsubscribe from all the topics for c client, only for the server side though
	if c.sess != nil {
		topics, _, err := c.sess.Topics()
		if err != nil {
			glog.Errorf("(%s/%d): %v", c.getcid(), c.cid, err)
		} else {
			for _, t := range topics {
				if err := c.topicsMgr.Unsubscribe([]byte(t), c); /*&c.onpub);*/ err != nil {
					glog.Errorf("(%s): Error unsubscribing topic %q: %v", c.getcid(), t, err)
				}
			}
		}
	}

	// Publish will message if WillFlag is set. Server side only.
	if c.sess != nil && c.sess.Cmsg.WillFlag() {
		glog.Infof("(%s) client/stop: connection unexpectedly closed. Sending Will.", c.getcid())
		c.onPublish(c.sess.Will)
	}

	// Remove the session from session store if it's suppose to be clean session
	if c.sess != nil && c.sess.Cmsg.CleanSession() && c.sessMgr != nil {
		c.sessMgr.Del(c.sess.ID())
	}

	// c.nc = nil
}

func (c *client) closeConnection() {
	// c.Noticef("start %s connection closed", c.typeString())

	c.stop()

	c.mu.Lock()
	if c.nc == nil {
		c.mu.Unlock()
		return
	}

	c.Noticef("%s connection closed", c.typeString())

	c.clearAuthTimer()
	c.clearPingTimer()
	c.clearConnection()
	c.nc = nil

	// Snapshot for use.
	subs := make([]*subscription, 0, len(c.subs))
	for _, sub := range c.subs {
		// Auto-unsubscribe subscriptions must be unsubscribed forcibly.
		sub.max = 0
		subs = append(subs, sub)
	}
	srv := c.srv

	var (
		routeClosed   bool
		retryImplicit bool
		connectURLs   []string
	)
	if c.route != nil {
		routeClosed = c.route.closed
		if !routeClosed {
			retryImplicit = c.route.retry
		}
		connectURLs = c.route.connectURLs
	}

	c.mu.Unlock()

	if srv != nil {
		// This is a route that disconnected...
		if len(connectURLs) > 0 {
			// Unless disabled, possibly update the server's INFO protcol
			// and send to clients that know how to handle async INFOs.
			if !srv.getOpts().Cluster.NoAdvertise {
				srv.removeClientConnectURLsAndSendINFOToClients(connectURLs)
			}
		}

		// Unregister
		srv.removeClient(c)

		// Remove clients subscriptions.
		for _, sub := range subs {
			srv.sl.Remove(sub)
			// Forward on unsubscribes if we are not
			// a router ourselves.
			if c.typ != ROUTER {
				srv.broadcastUnSubscribe(sub)
			}
		}
	}

	// Don't reconnect routes that are being closed.
	if routeClosed {
		return
	}

	// Check for a solicited route. If it was, start up a reconnect unless
	// we are already connected to the other end.
	if c.isSolicitedRoute() || retryImplicit {
		// Capture these under lock
		c.mu.Lock()
		rid := c.route.remoteID
		rtype := c.route.routeType
		rurl := c.route.url
		c.mu.Unlock()

		srv.mu.Lock()
		defer srv.mu.Unlock()

		// It is possible that the server is being shutdown.
		// If so, don't try to reconnect
		if !srv.running {
			return
		}

		if rid != "" && srv.remotes[rid] != nil {
			c.srv.Debugf("Not attempting reconnect for solicited route, already connected to \"%s\"", rid)
			return
		} else if rid == srv.info.ID {
			c.srv.Debugf("Detected route to self, ignoring \"%s\"", rurl)
			return
		} else if rtype != Implicit || retryImplicit {
			c.srv.Debugf("Attempting reconnect for solicited route \"%s\"", rurl)
			// Keep track of c go-routine so we can wait for it on
			// server shutdown.
			srv.startGoRoutine(func() { srv.reConnectToRoute(rurl, rtype) })
		}
	}
}

// If the client is a route connection, sets the `closed` flag to true
// to prevent any reconnecting attempt when c.closeConnection() is called.
func (c *client) setRouteNoReconnectOnClose() {
	c.mu.Lock()
	if c.route != nil {
		c.route.closed = true
	}
	c.mu.Unlock()
}

// Logging functionality scoped to a client or route.

func (c *client) Errorf(format string, v ...interface{}) {
	format = fmt.Sprintf("%s - %s", c, format)
	c.srv.Errorf(format, v...)
}

func (c *client) Debugf(format string, v ...interface{}) {
	format = fmt.Sprintf("%s - %s", c, format)
	c.srv.Debugf(format, v...)
}

func (c *client) Noticef(format string, v ...interface{}) {
	format = fmt.Sprintf("%s - %s", c, format)
	c.srv.Noticef(format, v...)
}

func (c *client) Tracef(format string, v ...interface{}) {
	format = fmt.Sprintf("%s - %s", c, format)
	c.srv.Tracef(format, v...)
}
