extends Reference
class_name UUID

var data: PoolByteArray

func _init(data := PoolByteArray()) -> void:
	self.data = data

func _to_string() -> String:
	return data.hex_encode() 

func valid() -> bool:
	return data.size() == 16
