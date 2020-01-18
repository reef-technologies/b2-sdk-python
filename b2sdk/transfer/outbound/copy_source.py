class CopySource(object):
    def __init__(
        self, file_id, content_length=None, file_info=None, offset=0, small_file_promise=False
    ):
        self.file_id = file_id
        if self.content_length is not None and small_file_promise:
            raise ValueError('Cannot promise small file of known content length')
        self.content_length = content_length
        self.file_info = file_info
        if self.offset > 0 and small_file_promise:
            raise ValueError('Cannot offset in promissed small file')
        self.offset = offset
        self.small_file_promise = small_file_promise

    def get_bytes_range(self):
        if self.content_length is None:
            if self.offset > 0:
                # auto mode should get file info and create correct copy source (with content_length)
                raise ValueError('cannot return bytes range for non zero offset and unknown length')
            return None

        return (self.offset, self.offset + self.content_length - 1)


class CopySourcePart(object):
    def __init__(self, copy_source, part_number, source_offset=0, part_length=None):
        self.copy_source = copy_source
        if source_offset > 0 and part_length is None:
            raise ValueError('Cannot set offset for unknown length')
        self.source_offset = source_offset
        self.part_length = part_length
        self.part_number = part_number

    def get_bytes_range(self):
        if self.part_length is None:
            return None

        return (self.source_offset, self.source_offset + self.part_length - 1)
