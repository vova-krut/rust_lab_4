use bcrypt::{hash, verify, DEFAULT_COST};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use futures::stream::{SplitSink, SplitStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio_tungstenite::{accept_async, WebSocketStream};
use tokio_tungstenite::tungstenite::Message;

// --- Data Structures ---

#[derive(Clone, Serialize, Deserialize)]
struct ChatMessage {
    username: String,
    content: String,
    timestamp: i64,
}

#[derive(Serialize, Deserialize)]
struct AuthInfo {
    auth_type: AuthType,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
enum AuthType {
    REGISTRATION,
    LOGIN,
}

#[derive(Serialize)]
struct ServiceMessage {
    status: Status,
}

#[derive(Serialize)]
enum Status {
    SUCCESS,
    FAILED,
}

// --- Server Struct ---

struct WebSocketChatServer {
    chat_log: Arc<Mutex<Vec<ChatMessage>>>,
    user_db: Arc<Mutex<HashMap<String, String>>>,
    global_broadcaster: Sender<ChatMessage>,
}

impl WebSocketChatServer {
    fn new() -> Self {
        let (global_broadcaster, _): (Sender<ChatMessage>, Receiver<ChatMessage>) = broadcast::channel(100);
        Self {
            chat_log: Arc::new(Mutex::new(Vec::new())),
            user_db: Arc::new(Mutex::new(HashMap::new())),
            global_broadcaster,
        }
    }

    // --- Authentication Methods ---

    async fn register(&self, username: &str, password: &str) -> Result<(), &'static str> {
        let mut users = self.user_db.lock().await;

        if users.contains_key(username) {
            return Err("Username is already taken");
        }

        let hashed_password = hash(password, DEFAULT_COST).map_err(|_| "Password hashing failed")?;
        users.insert(username.to_string(), hashed_password);
        Ok(())
    }

    async fn authenticate(&self, username: &str, password: &str) -> bool {
        let users = self.user_db.lock().await;
        users.get(username).map_or(false, |hashed| verify(password, hashed).unwrap_or(false))
    }

    // --- Messaging Methods ---

    async fn send_history(&self, sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>) {
        let messages = self.chat_log.lock().await;
        for message in messages.iter() {
            if let Ok(serialized) = serde_json::to_string(message) {
                let _ = sender.send(serialized.into()).await;
            }
        }
    }

    async fn broadcast_message_globally(&self, message: ChatMessage) {
        let mut log = self.chat_log.lock().await;
        log.push(message.clone());
        let _ = self.global_broadcaster.send(message);
    }

    // --- Client Handling ---

    async fn handle_connection(&self, stream: TcpStream) {
        let websocket = match accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("WebSocket handshake failed: {}", e);
                return;
            }
        };

        let (mut sender, mut local_receiver) = websocket.split();
        let mut global_receiver = self.global_broadcaster.subscribe();

        if let Some(Ok(msg)) = local_receiver.next().await {
            if let Ok(auth) = serde_json::from_str::<AuthInfo>(&msg.to_string()) {
                if self.handle_auth(&auth, &mut sender).await.is_err() {
                    return;
                }
            }
        }

        self.send_history(&mut sender).await;

        self.listen_for_messages(&mut sender, &mut local_receiver, &mut global_receiver).await;
    }

    async fn handle_auth(
        &self,
        auth: &AuthInfo,
        sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    ) -> Result<(), ()> {
        let success_response = serde_json::to_string(&ServiceMessage { status: Status::SUCCESS }).unwrap();
        let failure_response = serde_json::to_string(&ServiceMessage { status: Status::FAILED }).unwrap();

        match auth.auth_type {
            AuthType::REGISTRATION => {
                if self.register(&auth.username, &auth.password).await.is_ok() {
                    let _ = sender.send(success_response.into()).await;
                } else {
                    let _ = sender.send(failure_response.into()).await;
                    return Err(());
                }
            }
            AuthType::LOGIN => {
                if self.authenticate(&auth.username, &auth.password).await {
                    let _ = sender.send(success_response.into()).await;
                } else {
                    let _ = sender.send(failure_response.into()).await;
                    return Err(());
                }
            }
        }
        Ok(())
    }

    async fn listen_for_messages(
        &self,
        sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
        local_receiver: &mut SplitStream<WebSocketStream<TcpStream>>,
        global_receiver: &mut Receiver<ChatMessage>,
    ) {
        loop {
            tokio::select! {
                Some(Ok(msg)) = local_receiver.next() => {
                    if let Ok(message) = serde_json::from_str::<ChatMessage>(&msg.to_string()) {
                        self.broadcast_message_globally(message).await;
                    }
                }
                Ok(broadcast_msg) = global_receiver.recv() => {
                    if let Ok(serialized) = serde_json::to_string(&broadcast_msg) {
                        let _ = sender.send(serialized.into()).await;
                    }
                }
            }
        }
    }
}

// --- Main Function ---

#[tokio::main]
async fn main() {
    let server = Arc::new(WebSocketChatServer::new());
    let listener = TcpListener::bind("localhost:8080").await.expect("Failed to bind server");

    println!("WebSocket server running on ws://localhost:8080");

    while let Ok((socket, _)) = listener.accept().await {
        let server_clone = Arc::clone(&server);
        tokio::spawn(async move {
            server_clone.handle_connection(socket).await;
        });
    }
}
