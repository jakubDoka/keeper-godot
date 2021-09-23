extends Reference
class_name Binary

var buffer := PoolByteArray()
var offset: int

func _init(data := PoolByteArray()) -> void:
	buffer = data

func write_rest(bytes: PoolByteArray) -> void:
	buffer.append_array(bytes)

func read_rest() -> PoolByteArray:
	return buffer.subarray(offset, buffer.size() - 1)

func write_uint32(value: int) -> void:
	buffer.append_array([value >> 24, value >> 16, value >> 8, value])

func read_uint32() -> int:
	var next_offset := offset + 4
	if next_offset >= buffer.size(): return -1
	
	var result := (buffer[offset] << 24) + (buffer[offset + 1] << 16) +\
		(buffer[offset + 2] << 8) + buffer[offset + 3]
	offset = next_offset
	
	return result

func write_bytes(bytes: PoolByteArray) -> void:
	write_uint32(bytes.size())
	buffer.append_array(bytes) 

func read_bytes():
	var size := read_uint32()
	if size == -1: return null
	
	var next_offset := offset + size
	if next_offset >= buffer.size(): return -1
	
	var result := buffer.subarray(offset, next_offset - 1)
	offset = next_offset
	
	return result

func write_string(string: String) -> void:
	write_bytes(string.to_ascii())

func read_string():
	var bytes = read_bytes()
	if bytes != null: return bytes.get_string_from_ascii()
	return null

func write_uuid(value: UUID) -> void:
	assert(value.valid())
	buffer.append_array(value.data)

func read_uuid() -> UUID:
	var next_offset := offset + 16
	if next_offset > buffer.size(): return null
	
	var result = buffer.subarray(offset, next_offset - 1)
	offset = next_offset
	
	return UUID.new(result)

func write_aes(value: AES) -> void:
	buffer.append_array(value.key)
	buffer.append_array(value.iv)

func read_aes() -> AES:
	var next_offset: int = offset + AES.KEY_SIZE + AES.IV_SIZE
	if next_offset > buffer.size(): return null

	var result = buffer.subarray(offset, next_offset - 1)
	offset = next_offset

	return AES.new(result)

func write_uuid_array(values: Array) -> void:
	write_uint32(values.size())
	for value in values: write_uuid(value)
