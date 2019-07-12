void send_messages(CommParty* commParty, string * messages, int start, int end) {
	for (int i = start; i < end; i++) {
		auto s = messages[i];
		print_send_message(s, i);
		commParty->write((const byte *)s.c_str(), s.size());
	}
}
