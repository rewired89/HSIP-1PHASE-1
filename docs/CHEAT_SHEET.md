HSIP CLI — Quick Demo Cheat Sheet


1) Create identity
cargo run -p hsip-cli -- init


2) Publish a HELLO (signed)
cargo run -p hsip-cli -- hello
or
cargo run -p hsip-cli -- hello-send --to 1.2.3.4:40404


3) Start control listener (reply allow)
cargo run -p hsip-cli -- consent-listen --addr 127.0.0.1:9100 --decision allow --ttl-ms 30000


4) Make a consent request and wait for reply
echo hello > demo.txt
cargo run -p hsip-cli -- consent-request --file demo.txt --purpose demo --expires-ms 60000 --out req.json
cargo run -p hsip-cli -- consent-send-request --to 127.0.0.1:9100 --file req.json --wait-reply


5) Session demo (sealed UDP)
Listener: cargo run -p hsip-cli -- session-listen --addr 127.0.0.1:50505
Sender : cargo run -p hsip-cli -- session-send --to 127.0.0.1:50505 --packets 5


6) Privacy Ping (sealed roundtrip RTT)
Listener: cargo run -p hsip-cli -- ping-listen --addr 127.0.0.1:51515
Sender : cargo run -p hsip-cli -- ping --to 127.0.0.1:51515 --count 3


Notes:
- Logs prefixed by [session-listen] / [control-listen] / [ping] etc.
- Use --cover for sealed cover traffic (session-listen/session-send).