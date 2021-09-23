extends Object
class_name ServerPacket

var code: int
var data: PoolByteArray

func _init(raw: PoolByteArray) -> void:
	var cursor := Binary.new(raw)
	code = cursor.read_uint32()
	data = raw.subarray(4, raw.size()-1)
