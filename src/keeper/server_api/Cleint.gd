extends Node
class_name NetClient

enum Code {
	error = 0
	connection_request
	match_join_fail
	match_join_success
}

class RPCResponse:
	var code: int
	var headers: Dictionary
	var body = PoolByteArray()
	
	func is_ok() -> bool:
		return code == HTTPClient.RESPONSE_OK

class Player:
	var id: UUID
	var session: UUID
	var ip: String
	
	func _init(id: UUID, session: UUID, ip: String) -> void:
		self.id = id
		self.session = session
		self.ip = ip
	
	func _to_string() -> String:
		return "session: %s id: %s ip: %s" % [session, id, ip]

var player: Player

var enc: AES
var dec: AES

var host: String
var port: int
var ssl: bool
var secure: bool

var tcp := StreamPeerTCP.new()
var udp := PacketPeerUDP.new()
var http := HTTPClient.new()

signal packet(packet) # ServerPacket
signal error(error) # String
signal closed()
signal match_join_success(meta) # PoolByteArray
signal match_join_fail(message) # String

func _init(host := "127.0.0.1", port := 8080, ssl := false, secure := false) -> void:
	set_process(false)
	self.host = host
	self.port = port
	self.ssl = ssl
	self.secure = secure
	tcp.big_endian = true
	

func connect_http_async() -> void:
	http.connect_to_host(host, port+1, ssl, secure)
	
	while http.get_status() != HTTPClient.STATUS_CONNECTED:
		yield(Engine.get_main_loop(), "idle_frame")
		http.poll()
		if http.get_status() == HTTPClient.STATUS_CANT_CONNECT:
			return

func connect_tcp_udp_async() -> void:
	yield(get_tree().create_timer(0), "timeout")
	# tcp handshake
	tcp.connect_to_host(host, port)
	while true:
		if tcp.get_status() == StreamPeerTCP.STATUS_CONNECTING:
			yield(Engine.get_main_loop(), "idle_frame")
		elif tcp.get_status() == StreamPeerTCP.STATUS_CONNECTED:
			break
		else:
			printerr("Failed to connect tcp.")
	var cursor := Binary.new()
	send_packet(Code.connection_request)
	
	# udp handshake
	udp.connect_to_host(host, port)
	send_packet(Code.connection_request, [], [], true)

	set_process(true)

func _process(delta: float) -> void:
	if not tcp.is_connected_to_host():
		emit_signal("closed")
		set_process(false)
		return
	if tcp.get_available_bytes() != 0:  
		var size := tcp.get_u32()
		var result := tcp.get_data(size)
		if result[0] == OK:
			 on_packet(result[1], true)
		else:
			printerr("failed to read tcp packet: ", result[0])
	for i in range(udp.get_available_packet_count()):
		on_packet(udp.get_packet())

func on_packet(raw: PoolByteArray, refresh := false) -> void:
	raw = dec.decrypt(raw, refresh)
	var packet := ServerPacket.new(raw)
	match packet.code:
		Code.error:
			emit_signal("error", packet.data.get_string_from_ascii())
		Code.match_join_fail:
			emit_signal("match_join_fail", packet.data.get_string_from_ascii())
		Code.match_join_success:
			emit_signal("match_join_success", packet.data)
		_:
			emit_signal("packet", packet)

func send_packet(
	code: int, 
	data := PoolByteArray(), 
	targets := PoolStringArray(), 
	udp := false
) -> void:
	assert(enc)
	assert(player)
	
	var cursor := Binary.new()
	cursor.write_uuid(player.session)
	cursor.write_uint32(code)
	cursor.write_uuid_array(targets)
	cursor.write_rest(data)
	
	var cipher_text: PoolByteArray = enc.encrypt(cursor.buffer, not udp)
	cursor = Binary.new()
	if not udp: cursor.write_uint32(16 + cipher_text.size())
	cursor.write_uuid(player.id)
	cursor.write_rest(cipher_text)

	if udp: self.udp.put_packet(cursor.buffer)
	else: self.tcp.put_data(cursor.buffer)

func rpc_async( 
	id: String,
	data := PoolByteArray(), 
	format := "application/json",
	meta := ""
) -> RPCResponse:
	var headers: PoolStringArray = ["id: " + id]
	if meta: headers.append("meta: " + meta)
	if player: headers.append("session: " + str(player.session))
	var error := http.request_raw(HTTPClient.METHOD_POST, "/rpc", headers, data)
	assert(error == OK)
	var response := RPCResponse.new()
	
	while http.get_status() == HTTPClient.STATUS_REQUESTING:
		http.poll()
		yield(Engine.get_main_loop(), "idle_frame")

	if not http.has_response(): return null

	response.code = http.get_response_code()
	response.headers = http.get_response_headers_as_dictionary()
	http.read_chunk_size = clamp(http.get_response_body_length(), 256, 1 << 24)
	var body := PoolByteArray()
	while http.get_status() == HTTPClient.STATUS_BODY:
		http.poll()
		body.append_array(http.read_response_body_chunk()) 
	response.body = body
	return response

func register_email_async(email: String, password: String, meta: PoolByteArray) -> String:
	var cursor := Binary.new()
	cursor.write_string(email)
	cursor.write_string(password)
	cursor.write_rest(meta)
	
	var response: RPCResponse = yield(rpc_async(
		"register-email",
		cursor.buffer,
		"application/octet-stream"
	), "completed")
	
	if not response.is_ok():
		return response.body.get_string_from_ascii()
	
	return ""

func login_email_async(email: String, password: String) -> String:
	var cursor := Binary.new()
	cursor.write_string(email)
	cursor.write_string(password)
	
	var response: RPCResponse = yield(rpc_async(
		"login-email", 
		cursor.buffer, 
		"application/octet-stream"
	), "completed")
	
	if not response.is_ok():
		return response.body.get_string_from_ascii()
	
	cursor = Binary.new(response.body)
	
	player = Player.new(cursor.read_uuid(), cursor.read_uuid(), cursor.read_string())
	enc = cursor.read_aes()
	if not enc: return "server sent malformed packet (bruh)"
	cursor.offset -= AES.KEY_SIZE + AES.IV_SIZE
	dec = cursor.read_aes()
	
	return ""

class Match:
	var id: UUID
	var error: String

func create_match_async(type: String, meta := PoolByteArray()) -> Match:
	var cursor := Binary.new()
	cursor.write_string(type)
	cursor.write_rest(meta)
	
	var resp: RPCResponse = yield(rpc_async(
		"create-match",
		cursor.buffer,
		"application/octet-stream"
	), "completed")
	
	var m := Match.new()
	
	if not resp.is_ok():
		m.error = resp.body.get_string_from_ascii()
	else:
		m.id = UUID.new(resp.body)
	
	return m

func join_match_async(m: Match, meta := PoolByteArray()) -> void:
	yield(connect_tcp_udp_async(), "completed")
	
	var cursor := Binary.new()
	cursor.write_uuid(m.id)
	cursor.write_rest(meta)
	
	send_packet(0, cursor.buffer, [])
