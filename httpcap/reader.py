from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'


class DataReader(object):
    """ wrap http data for read. """

    def __init__(self, data_list):
        """
        :type data_list: list
        """
        self.data_list = data_list
        self.idx = 0
        self.data = None
        self.finish = False

    def _read(self):
        if self.idx >= len(self.data_list):
            self.finish = True
            return None
        item = self.data_list[self.idx]
        self.idx += 1
        return item

    def read_line(self):
        """read line from input data"""
        if self.finish:
            return None

        buffers = []
        if not self.data:
            self.data = self._read()
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self._read()
                continue

            idx = self.data.find(b'\n')
            if idx >= 0:
                buffers.append(self.data[0:idx + 1])
                self.data = self.data[idx + 1:]
                break
            if self.data:
                buffers.append(self.data)
            self.data = self._read()

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

        buffers = []
        read_size = 0
        if not self.data:
            self.data = self._read()
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self._read()
                continue

            if len(self.data) >= size - read_size:
                buffers.append(self.data[0:size - read_size])
                self.data = self.data[size - read_size:]
                break

            if self.data:
                buffers.append(self.data)
                read_size += len(self.data)
            self.data = self._read()

        if not buffers and self.finish:
            return None
        return b''.join(buffers)

    def skip(self, size):
        if self.finish:
            return -1

        read_size = 0
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self._read()
                continue

            if len(self.data) >= size - read_size:
                self.data = self.data[size - read_size:]
                read_size = size
                break

            read_size += len(self.data)
            self.data = self._read()

        return read_size

    def read_all(self):
        if self.finish:
            return None

        buf = []
        if self.data:
            buf.append(self.data)
        while True:
            data = self._read()
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
            data = self._read()
            if data is None:
                break

    def finish(self):
        return self.finish