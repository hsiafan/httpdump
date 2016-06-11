from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'
from six.moves import queue


class DataReader(object):
    """
    Wrap data sequence to reader.
    Producer thread use send_data and finish,
    Consumer thread use all read methods
    """
    FINISH = object()

    def __init__(self):
        self.data_queue = queue.Queue()
        self.data = None
        self.finish = False

    def send_data(self, data):
        """
        Send data to this reader
        """
        self.data_queue.put(data)

    def send_finish(self):
        """
        Finish this reader
        """
        self.data_queue.put(DataReader.FINISH)

    def next_data(self):
        if self.finish:
            return None
        data = self.data_queue.get()
        if data == DataReader.FINISH:
            self.finish = True
            return None
        return data

    def read_line(self):
        """read line from input data"""
        if self.finish:
            return None

        buffers = []
        if not self.data:
            self.data = self.next_data()
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self.next_data()
                continue

            idx = self.data.find(b'\n')
            if idx >= 0:
                buffers.append(self.data[0:idx + 1])
                self.data = self.data[idx + 1:]
                break
            if self.data:
                buffers.append(self.data)
            self.data = self.next_data()

        if not buffers and self.finish:
            return None
        return b''.join(buffers)

    def fetch_line(self):
        """fetch a line, but not modify pos"""
        line = self.read_line()
        if line is None:
            return None

        if self.data:
            self.data += line
        else:
            self.data = line

        # self.finish may be True, mark it as False
        if self.data:
            self.finish = False
        return line

    def read(self, size):
        if self.finish:
            return None

        if size == 0:
            return b''
        buffers = []
        read_size = 0
        if not self.data:
            self.data = self.next_data()
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self.next_data()
                continue

            if len(self.data) >= size - read_size:
                buffers.append(self.data[0:size - read_size])
                self.data = self.data[size - read_size:]
                break

            if self.data:
                buffers.append(self.data)
                read_size += len(self.data)
            self.data = self.next_data()

        if not buffers and self.finish:
            return None
        return b''.join(buffers)

    def skip(self, size):
        if self.finish:
            return -1

        read_size = 0
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self.next_data()
                continue

            if len(self.data) >= size - read_size:
                self.data = self.data[size - read_size:]
                read_size = size
                break

            read_size += len(self.data)
            self.data = self.next_data()

        return read_size

    def read_all(self):
        if self.finish:
            return None

        buf = []
        if self.data:
            buf.append(self.data)
        while True:
            data = self.next_data()
            if data is None:
                break
            if self.data:
                buf.append(data)

        if not buf and self.finish:
            return None
        return b''.join(buf)

    def skip_all(self):
        if self.finish:
            return

        while True:
            data = self.next_data()
            if data is None:
                break