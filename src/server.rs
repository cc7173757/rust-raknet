use std::collections::HashMap;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, Notify, RwLock};

use crate::error::{RaknetError, Result};
use crate::packet::*;
use crate::utils::*;
use crate::{raknet_log_debug, raknet_log_error, socket::*};

const SERVER_NAME: &str = "Rust Raknet Server";
const MAX_CONNECTION: u32 = 99999;

type SessionSender = (i64, Sender<Vec<u8>>);

type QueryPacket = (SocketAddr, Vec<u8>);

/// Implementation of Raknet Server.
pub struct RaknetListener {
    motd: Arc<RwLock<String>>,
    socket: Option<Arc<UdpSocket>>,
    guid: u64,
    listened: bool,
    connection_receiver: Receiver<RaknetSocket>,
    connection_sender: Sender<RaknetSocket>,
    sessions: Arc<Mutex<HashMap<SocketAddr, SessionSender>>>,
    close_notifier: Arc<tokio::sync::Semaphore>,
    all_session_closed_notifier: Arc<Notify>,
    drop_notifier: Arc<Notify>,
    version_map: Arc<Mutex<HashMap<String, u8>>>,
    /// RakNet encryption is not supported so if it is true, it will only check cookie.
    use_encryption: bool,
    cookie_map: Arc<Mutex<HashMap<String, u32>>>,
    receive_timeout: u64,
    query_sender: Sender<QueryPacket>,
    query_receiver: Arc<Mutex<Receiver<QueryPacket>>>,
}

impl RaknetListener {
    /// Creates a new RaknetListener which will be bound to the specified address.
    ///
    /// # Example
    /// ```ignore
    /// let mut listener = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// listener.listen().await;
    /// let mut socket = socket = listener.accept().await.unwrap();
    /// ```
    pub async fn bind(sockaddr: &SocketAddr) -> Result<Self> {
        Self::bind_with(sockaddr, false, None).await
    }

    pub async fn bind_with(
        sockaddr: &SocketAddr,
        use_encryption: bool,
        receive_timeout: Option<u64>,
    ) -> Result<Self> {
        let s = match UdpSocket::bind(sockaddr).await {
            Ok(p) => p,
            Err(_) => {
                return Err(RaknetError::BindAddressError);
            }
        };

        let (connection_sender, connection_receiver) = channel::<RaknetSocket>(10);

        let (query_sender, query_receiver) = channel::<QueryPacket>(10);

        let ret = Self {
            motd: Arc::new(RwLock::new(String::new())),
            socket: Some(Arc::new(s)),
            guid: rand::random(),
            listened: false,
            connection_receiver,
            connection_sender,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            close_notifier: Arc::new(tokio::sync::Semaphore::new(0)),
            all_session_closed_notifier: Arc::new(Notify::new()),
            drop_notifier: Arc::new(Notify::new()),
            version_map: Arc::new(Mutex::new(HashMap::new())),
            use_encryption,
            cookie_map: Arc::new(Mutex::new(HashMap::new())),
            receive_timeout: receive_timeout.unwrap_or(DEFAULT_RECEIVE_TIMEOUT),
            query_sender,
            query_receiver: Arc::new(Mutex::new(query_receiver)),
        };

        ret.drop_watcher().await;
        Ok(ret)
    }

    /// Creates a new RaknetListener from a UdpSocket.
    ///
    /// # Example
    /// ```ignore
    /// let raw_socket = std::net::UdpSocket::bind("127.0.0.1:19132").unwrap();
    /// let listener = RaknetListener::from_std(raw_socket);
    /// ```
    pub async fn from_std(
        s: std::net::UdpSocket,
        use_encryption: bool,
        receive_timeout: Option<u64>,
    ) -> Result<Self> {
        s.set_nonblocking(true)
            .expect("set udpsocket nonblocking error");

        let s = match UdpSocket::from_std(s) {
            Ok(p) => p,
            Err(_) => {
                return Err(RaknetError::SetRaknetRawSocketError);
            }
        };

        let (connection_sender, connection_receiver) = channel::<RaknetSocket>(10);

        let (query_sender, query_receiver) = channel::<QueryPacket>(10);

        let ret = Self {
            motd: Arc::new(RwLock::new(String::new())),
            socket: Some(Arc::new(s)),
            guid: rand::random(),
            listened: false,
            connection_receiver,
            connection_sender,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            close_notifier: Arc::new(tokio::sync::Semaphore::new(0)),
            all_session_closed_notifier: Arc::new(Notify::new()),
            drop_notifier: Arc::new(Notify::new()),
            version_map: Arc::new(Mutex::new(HashMap::new())),
            use_encryption,
            cookie_map: Arc::new(Mutex::new(HashMap::new())),
            receive_timeout: receive_timeout.unwrap_or(DEFAULT_RECEIVE_TIMEOUT),
            query_sender,
            query_receiver: Arc::new(Mutex::new(query_receiver)),
        };

        ret.drop_watcher().await;
        Ok(ret)
    }

    async fn start_session_collect(
        &self,
        socket: &Arc<UdpSocket>,
        sessions: &Arc<Mutex<HashMap<SocketAddr, SessionSender>>>,
        mut collect_receiver: Receiver<SocketAddr>,
    ) {
        let sessions = sessions.clone();
        let socket = socket.clone();
        let close_notifier = self.close_notifier.clone();
        let all_session_closed_notifier = self.all_session_closed_notifier.clone();
        tokio::spawn(async move {
            loop {
                let addr: SocketAddr;

                tokio::select! {
                    a = collect_receiver.recv() => {
                        match a {
                            Some(p) => { addr = p },
                            None => {
                                raknet_log_debug!("session collecter closed");
                                break;
                            },
                        };
                    },
                    _ = close_notifier.acquire() => {
                        raknet_log_debug!("session collecter close notified");
                        break;
                    }
                }

                let mut sessions = sessions.lock().await;
                if sessions.contains_key(&addr) {
                    match socket.send_to(&[PacketID::Disconnect.to_u8()], addr).await {
                        Ok(_) => {}
                        Err(e) => {
                            raknet_log_error!("udp socket send_to error : {}", e);
                        }
                    };
                    sessions.remove(&addr);
                    raknet_log_debug!("collect socket : {}", addr);
                }
            }

            let mut sessions = sessions.lock().await;

            for i in sessions.iter() {
                i.1 .1.send(vec![PacketID::Disconnect.to_u8()]).await.ok();

                match socket.send_to(&[PacketID::Disconnect.to_u8()], i.0).await {
                    Ok(_) => {}
                    Err(e) => {
                        raknet_log_error!("udp socket send_to error : {}", e);
                    }
                };
            }

            while !sessions.is_empty() {
                let addr = match collect_receiver.recv().await {
                    Some(p) => p,
                    None => {
                        raknet_log_error!("clean session faild , maybe has session not close");
                        break;
                    }
                };

                if sessions.contains_key(&addr) {
                    match socket.send_to(&[PacketID::Disconnect.to_u8()], addr).await {
                        Ok(_) => {}
                        Err(e) => {
                            raknet_log_error!("udp socket send_to error : {}", e);
                        }
                    };
                    sessions.remove(&addr);
                    raknet_log_debug!("collect socket : {}", addr);
                }
            }

            sessions.clear();
            all_session_closed_notifier.notify_one();

            raknet_log_debug!("session collect closed");
        });
    }

    /// Listen to a RaknetListener
    ///
    /// This method must be called before calling RaknetListener::accept()
    ///
    /// # Example
    /// ```ignore
    /// let mut listener = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// listener.listen().await;
    /// ```
    pub async fn listen(&mut self) {
        if self.close_notifier.is_closed() || self.listened {
            return;
        }

        if self.get_motd().await.is_empty() {
            let port = self.socket.as_ref().unwrap().local_addr().unwrap().port();

            self.set_motd(
                "MCPE",
                SERVER_NAME,
                748,
                "1.21.40",
                0,
                MAX_CONNECTION,
                None,
                "rust-raknet",
                "Survival",
                true,
                port,
                port,
            )
            .await;
        }

        let socket = self.socket.as_ref().unwrap().clone();
        let guid = self.guid;
        let sessions = self.sessions.clone();
        let connection_sender = self.connection_sender.clone();
        let motd = self.motd.clone();

        self.listened = true;

        let (collect_sender, collect_receiver) = channel::<SocketAddr>(10);
        let collect_sender = Arc::new(Mutex::new(collect_sender));
        self.start_session_collect(&socket, &sessions, collect_receiver)
            .await;

        let local_addr = socket.local_addr().unwrap();
        let close_notify = self.close_notifier.clone();
        let version_map = self.version_map.clone();
        let use_encryption = self.use_encryption;
        let cookie_map = self.cookie_map.clone();
        let receive_timeout = self.receive_timeout;
        let query_sender = self.query_sender.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];

            raknet_log_debug!("start listen worker : {}", local_addr);

            loop {
                let motd = motd.clone();
                let size: usize;
                let addr: SocketAddr;

                tokio::select! {
                    a = socket.recv_from(&mut buf) => {
                        match a {
                            Ok(p) => {
                                size = p.0;
                                addr = p.1;
                            },
                            Err(e) => {
                                raknet_log_debug!("server recv_from error {}" , e);
                                break;
                            },
                        };
                    },
                    _ = close_notify.acquire() => {
                        raknet_log_debug!("listen close notified");
                        break;
                    }
                }

                // Check if it is Query Protocol.
                if buf[0] == 0xFE && buf[1] == 0xFD {
                    raknet_log_debug!("received a Query Protocol packet");
                    query_sender.send((addr, buf.to_vec())).await.ok();
                    continue;
                }

                let cur_status = match PacketID::from(buf[0]) {
                    Ok(p) => p,
                    Err(e) => {
                        raknet_log_debug!("parse PacketID failed : {:?}", e);
                        continue;
                    }
                };

                match cur_status {
                    PacketID::UnconnectedPing1 => {
                        let _ping = match read_packet_ping(&buf[..size]) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        let motd = { (*motd.read().await).clone() };

                        let packet = crate::packet::PacketUnconnectedPong {
                            time: cur_timestamp_millis(),
                            guid,
                            magic: true,
                            motd,
                        };

                        let pong = match write_packet_pong(&packet) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        match socket.send_to(&pong, addr).await {
                            Ok(_) => {}
                            Err(e) => {
                                raknet_log_error!("udp socket send_to error : {}", e);
                            }
                        };
                        continue;
                    }
                    PacketID::UnconnectedPing2 => {
                        match read_packet_ping(&buf[..size]) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        let motd = { (*motd.read().await).clone() };

                        let packet = crate::packet::PacketUnconnectedPong {
                            time: cur_timestamp_millis(),
                            guid,
                            magic: true,
                            motd,
                        };

                        let pong = match write_packet_pong(&packet) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        match socket.send_to(&pong, addr).await {
                            Ok(_) => {}
                            Err(e) => {
                                raknet_log_error!("udp socket send_to error : {}", e);
                            }
                        };
                        continue;
                    }
                    PacketID::OpenConnectionRequest1 => {
                        let req = match read_packet_connection_open_request_1(&buf[..size]) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        if !RAKNET_PROTOCOL_VERSION_LIST
                            .as_slice()
                            .contains(&req.protocol_version)
                        {
                            let packet = crate::packet::IncompatibleProtocolVersion {
                                server_protocol: RAKNET_PROTOCOL_VERSION,
                                magic: true,
                                server_guid: guid,
                            };
                            let buf = write_packet_incompatible_protocol_version(&packet).unwrap();

                            match socket.send_to(&buf, addr).await {
                                Ok(_) => {}
                                Err(e) => {
                                    raknet_log_error!("udp socket send_to error : {}", e);
                                }
                            };
                            continue;
                        }
                        {
                            let mut version_map = version_map.lock().await;
                            version_map.insert(addr.to_string(), req.protocol_version);
                        }

                        // A random cookie to prevent IP spoofing.
                        let cookie = if use_encryption {
                            let cookie = rand::random();

                            {
                                let mut cookie_map = cookie_map.lock().await;
                                cookie_map.insert(addr.to_string(), cookie);
                            }

                            Some(cookie)
                        } else {
                            None
                        };

                        let packet = crate::packet::OpenConnectionReply1 {
                            magic: true,
                            guid,
                            // Make sure this is false, it is vital for the login sequence to continue
                            use_encryption: if use_encryption { 0x01 } else { 0x00 },
                            cookie,
                            // see Open Connection Request 1
                            mtu_size: RAKNET_CLIENT_MTU,
                        };

                        let reply = match write_packet_connection_open_reply_1(&packet) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        match socket.send_to(&reply, addr).await {
                            Ok(_) => {}
                            Err(e) => {
                                raknet_log_error!("udp socket send_to error : {}", e);
                            }
                        };
                        continue;
                    }
                    PacketID::OpenConnectionRequest2 => {
                        let req = match read_packet_connection_open_request_2(
                            &buf[..size],
                            use_encryption,
                        ) {
                            Ok(p) => p,
                            Err(err) => {
                                raknet_log_error!("Oh: {:?}", err);
                                continue;
                            }
                        };

                        // If the server enabled RakNet encryption, check the cookie is valid.
                        if use_encryption {
                            let cookie = match req.cookie {
                                Some(cookie) => cookie,
                                None => {
                                    raknet_log_debug!("cookie must be provided");
                                    continue;
                                }
                            };
                            if req.support_encryption != Some(0x00) {
                                raknet_log_error!("RakNet encryption is not supported");
                                continue;
                            }

                            let saved_cookie = {
                                let cookie_map = cookie_map.lock().await;
                                cookie_map.get(&addr.to_string()).cloned()
                            };

                            if saved_cookie != Some(cookie) {
                                raknet_log_error!("the provided cookie is incorrect");
                                continue;
                            }
                        }

                        let packet = crate::packet::OpenConnectionReply2 {
                            magic: true,
                            guid,
                            address: addr,
                            mtu: req.mtu,
                            encryption_enabled: 0x00,
                        };

                        let reply = match write_packet_connection_open_reply_2(&packet) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        let mut sessions = sessions.lock().await;

                        if sessions.contains_key(&addr) {
                            let packet = write_packet_already_connected(&AlreadyConnected {
                                magic: true,
                                guid,
                            })
                            .unwrap();

                            match socket.send_to(&packet, addr).await {
                                Ok(_) => {}
                                Err(e) => {
                                    raknet_log_error!("udp socket send_to error : {}", e);
                                }
                            };

                            continue;
                        }

                        match socket.send_to(&reply, addr).await {
                            Ok(_) => {}
                            Err(e) => {
                                raknet_log_error!("udp socket send_to error : {}", e);
                            }
                        };

                        let (sender, receiver) = channel::<Vec<u8>>(10);

                        let raknet_version: u8;
                        {
                            let version_map = version_map.lock().await;
                            raknet_version = *version_map
                                .get(&addr.to_string())
                                .unwrap_or(&RAKNET_PROTOCOL_VERSION);
                        }

                        let s = RaknetSocket::from(
                            &addr,
                            &socket,
                            receiver,
                            req.mtu,
                            collect_sender.clone(),
                            raknet_version,
                            receive_timeout,
                            false,
                        )
                        .await;

                        raknet_log_debug!("accept connection : {}", addr);
                        sessions.insert(addr, (cur_timestamp_millis(), sender));
                        let _ = connection_sender.send(s).await;
                    }
                    PacketID::Disconnect => {
                        let mut sessions = sessions.lock().await;
                        if sessions.contains_key(&addr) {
                            sessions[&addr].1.send(buf[..size].to_vec()).await.unwrap();
                            sessions.remove(&addr);

                            // Remove the cookie if it is disconnected.
                            {
                                let mut cookie_map = cookie_map.lock().await;
                                cookie_map.remove(&addr.to_string());
                            }
                        }
                    }
                    _ => {
                        let mut sessions = sessions.lock().await;
                        if sessions.contains_key(&addr) {
                            match sessions[&addr].1.send(buf[..size].to_vec()).await {
                                Ok(_) => {}
                                Err(_) => {
                                    sessions.remove(&addr);

                                    // Remove the cookie if it is disconnected.
                                    {
                                        let mut cookie_map = cookie_map.lock().await;
                                        cookie_map.remove(&addr.to_string());
                                    }

                                    continue;
                                }
                            };
                            sessions.get_mut(&addr).unwrap().0 = cur_timestamp_millis();
                        }
                    }
                }
            }
            raknet_log_debug!("listen worker closed");
        });
    }

    /// Waiting for and receiving new Raknet connections, returning a Raknet socket
    ///
    /// Call this method must be after calling RaknetListener::listen()
    ///
    /// # Example
    /// ```ignore
    /// let mut listener = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// listener.listen().await;
    /// let mut socket = listener.accept().await.unwrap();
    /// ```
    pub async fn accept(&mut self) -> Result<RaknetSocket> {
        if !self.listened {
            return Err(RaknetError::NotListen);
        }

        tokio::select! {
            a = self.connection_receiver.recv() => {
                match a {
                    Some(p) => Ok(p),
                    None => {
                        Err(RaknetError::NotListen)
                    },
                }
            },
            _ = self.close_notifier.acquire() => {
                raknet_log_debug!("accept close notified");
                Err(RaknetError::NotListen)
            }
        }
    }

    /// Set the current motd, this motd will be provided to the client in the unconnected pong.
    ///
    /// Call this method must be after calling RaknetListener::listen()
    ///
    /// # Example
    /// ```ignore
    /// let mut listener = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// listener.set_motd("MCPE", "Another Minecraft Server", 748, "1.21.40", 3, 10, None, "Bedrock Level", "Survival", true, 19132, 19132).await;
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn set_motd(
        &mut self,
        edition: &str,
        motd: &str,
        mc_protocol_version: i32,
        mc_version: &str,
        player_count: u32,
        max_player_count: u32,
        server_id: Option<u64>,
        sub_motd: &str,
        game_type: &str,
        nintendo_allowed: bool,
        ipv4_port: u16,
        ipv6_port: u16,
    ) {
        let mut m = self.motd.write().await;
        *m = format!(
            "{};{};{};{};{};{};{};{};{};{};{};{};",
            edition,
            motd,
            mc_protocol_version,
            mc_version,
            player_count,
            max_player_count,
            server_id.unwrap_or(self.guid),
            sub_motd,
            game_type,
            if nintendo_allowed { "1" } else { "0" },
            ipv4_port,
            ipv6_port
        );
    }

    /// Get the current motd, this motd will be provided to the client in the unconnected pong.
    ///
    /// # Example
    /// ```ignore
    /// let listener = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// let motd = listener.get_motd().await;
    /// ```
    pub async fn get_motd(&self) -> String {
        self.motd.read().await.clone()
    }

    pub async fn motd(&self) -> Arc<RwLock<String>> {
        self.motd.clone()
    }

    /// Returns the socket address of the local half of this Raknet connection.
    ///
    /// # Example
    /// ```ignore
    /// let mut socket = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// assert_eq!(socket.local_addr().unwrap().ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    /// ```
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.as_ref().unwrap().local_addr().unwrap())
    }

    /// Close Raknet Server and all connections.
    ///
    /// # Example
    /// ```ignore
    /// let mut socket = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// socket.close().await;
    /// ```
    pub async fn close(&mut self) -> Result<()> {
        if self.close_notifier.is_closed() {
            return Ok(());
        }
        self.close_notifier.close();
        self.all_session_closed_notifier.notified().await;

        // wait all thread exit and drop socket pointer.
        while Arc::strong_count(self.socket.as_ref().unwrap()) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // drop socket and free bind port
        self.socket = None;
        self.listened = false;

        Ok(())
    }

    /// Set full motd string.
    ///
    /// # Example
    /// ```ignore
    /// let mut socket = RaknetListener::bind("127.0.0.1:19132".parse().unwrap()).await.unwrap();
    /// socket.set_full_motd("motd").await;
    /// ```
    pub async fn set_full_motd(&mut self, motd: String) -> Result<()> {
        let mut m = self.motd.write().await;
        *m = motd;
        Ok(())
    }

    pub async fn get_peer_raknet_version(&self, peer: &SocketAddr) -> Result<u8> {
        let version_map = self.version_map.lock().await;
        let ver = version_map.get(&peer.to_string());
        Ok(*ver.unwrap_or(&RAKNET_PROTOCOL_VERSION))
    }

    pub async fn get_peer_cookie(&self, peer: &SocketAddr) -> Result<Option<u32>> {
        let cookie_map = self.cookie_map.lock().await;
        let cookie = cookie_map.get(&peer.to_string()).cloned();
        Ok(cookie)
    }

    pub fn guid(&self) -> u64 {
        self.guid
    }

    pub async fn recv_query(&mut self) -> Result<QueryPacket> {
        if !self.listened {
            return Err(RaknetError::NotListen);
        }

        tokio::select! {
            packet = async { self.query_receiver.lock().await.recv().await } => {
                match packet {
                    Some(p) => Ok(p),
                    None => {
                        Err(RaknetError::NotListen)
                    },
                }
            },
            _ = self.close_notifier.acquire() => {
                raknet_log_debug!("recv_query close notified");
                Err(RaknetError::NotListen)
            }
        }
    }

    pub fn get_recv_query(&self) -> Result<Arc<Mutex<Receiver<QueryPacket>>>> {
        if !self.listened {
            return Err(RaknetError::NotListen);
        }

        Ok(self.query_receiver.clone())
    }

    async fn drop_watcher(&self) {
        let close_notifier = self.close_notifier.clone();
        let drop_notifier = self.drop_notifier.clone();
        tokio::spawn(async move {
            raknet_log_debug!("listener drop watcher start");
            drop_notifier.notify_one();

            drop_notifier.notified().await;

            if close_notifier.is_closed() {
                raknet_log_debug!("close notifier closed");
                return;
            }

            close_notifier.close();

            raknet_log_debug!("listener drop watcher closed");
        });

        self.drop_notifier.notified().await;
    }
}

impl Drop for RaknetListener {
    fn drop(&mut self) {
        self.drop_notifier.notify_one();
    }
}
