pub trait Network {
    fn send(&mut self, data: &[u8]);
}

#[cfg(feature = "std")]
pub mod std {
    use crate::network::Network;
    use std::{io, net::UdpSocket};

    pub struct StdNetwork {
        sock: UdpSocket,
    }

    impl StdNetwork {
        pub fn new(address: &str, port: u16) -> Self {
            let sock = UdpSocket::bind("0.0.0.0:0").expect("Fehler beim Erstellen des UDP sockets");
            sock.connect(&format!("{}:{}", address, port))
                .expect("Fehler beim setzen der Zieladresse des UDP sockets");
            Self { sock }
        }
    }

    impl Network for StdNetwork {
        fn send(&mut self, data: &[u8]) {
            self.sock.send(data).unwrap();
        }
    }
}

#[cfg(not(feature = "std"))]
pub mod m3 {
    use crate::network::Network;

    use m3::net::DGramSocket;
    use m3::net::DgramSocketArgs;
    use m3::net::Endpoint;
    use m3::net::IpAddr;
    use m3::net::UdpSocket;
    use m3::rc::Rc;
    use m3::session::NetworkManager;
    use m3::vfs::FileRef;

    pub struct M3Network {
        nm: Rc<NetworkManager>,
        sock: FileRef<UdpSocket>,
    }

    impl M3Network {
        pub fn new(address: &str, port: u16) -> Self {
            let nm = NetworkManager::new("net").unwrap();
            let mut sock = UdpSocket::new(DgramSocketArgs::new(nm.clone())).unwrap();
            sock.connect(Endpoint::new(address.parse::<IpAddr>().unwrap(), port));
            Self { nm, sock }
        }
    }

    impl Network for M3Network {
        fn send(&mut self, data: &[u8]) {
            self.sock.send(data).unwrap();
        }
    }
}
