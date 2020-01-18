from contextlib import contextmanager

from b2sdk.progress import RangeOfInputStream


class UploadSourcePart(object):
    def __init__(self, upload_source, source_offset, part_length, part_number):
        self.upload_source = upload_source
        self.source_offset = source_offset
        self.part_length = part_length
        self.part_number = part_number

    @contextmanager
    def range_of_input_stream(self):
        with self.upload_source.open() as file:
            file.seek(self.source_offset)  # FIXME: RangeOfInputStream should fo it in __init__
            yield RangeOfInputStream(file, self.source_offset, self.part_length)
