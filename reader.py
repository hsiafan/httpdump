#coding=utf8
__author__ = 'dongliu'


class ResetableWrapper(object):
    """a wrapper to distinct request and response datas."""

    def __init__(self, queue):
        self.queue = queue
        self.cur_httptype = None
        self.last_data = None
        self.finish = False

    def remains(self):
        return not self.finish

    def settype(self, httptype):
        self.cur_httptype = httptype

    def next_stream(self):
        if self.last_data:
            temp = self.last_data
            self.last_data = None
            yield temp

        while True:
            httptype, data = self.queue.get(block=True, timeout=None)
            if data is None:
                #None mean finish.
                break
            if httptype == self.cur_httptype:
                yield data
            else:
                # save for next
                self.last_data = data
                return
        self.finish = True


class DataReader(object):
    """ wrap http data for read. """

    def __init__(self, data_generator):
        self.data_generator = data_generator
        self.data = None
        self.finish = False

    def _read(self):
        try:
            data = self.data_generator.next()
            return data
        except StopIteration:
            self.finish = True
            return None

    def readline(self):
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

            idx = self.data.find('\n')
            if idx >= 0:
                buffers.append(self.data[0:idx + 1])
                self.data = self.data[idx + 1:]
                break
            if self.data:
                buffers.append(self.data)
            self.data = self._read()

        if not buffers and self.finish:
            return None
        return ''.join(buffers)

    def fetchline(self):
        """fetch a line, but not modify pos"""
        line = self.readline()
        if line is None:
            return None

        if self.data:
            self.data = line + self.data
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
        return ''.join(buffers)

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

    def readall(self):
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
        return ''.join(buf)

    def skipall(self):
        while self._read() is not None:
            pass

    def finish(self):
        return self.finish