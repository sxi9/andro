"""Pure text/binary parsers for everything the device gives us.

Each parser is a pure function (bytes/str in, data out) so the whole layer is
unit-testable without a device. Android dump formats drift between versions,
so every parser here is written tolerant-first: unknown lines are skipped,
never fatal.
"""
