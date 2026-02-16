#![no_std]

use m3::com::MemCap;
use m3::com::MemGate;
use m3::errors::Error;
use m3::kif::Perm;
use m3::server::server_loop;
use m3::server::RequestHandler;
use m3::server::RequestSession;
use m3::server::Server;
use m3::server::ServerSession;
use m3::server::DEF_MAX_CLIENTS;
use m3::server::DEF_MSG_SIZE;

// Session object that the server creates for every active session.
struct Session {
    // We hold onto the server’s session object.
    _serv: ServerSession,
    // The memory capability that we can send to the client on request.
    #[allow(dead_code)]
    mem: MemCap,
}

impl RequestSession for Session {
    /// Handler that is called whenever a new session is created.
    fn new(serv: ServerSession, _arg: &str) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // Write to a chunk of memory.
        let mem = MemGate::new(12, Perm::RW)?;
        mem.write(b"Hello World!", 0)?;
        Ok(Session {
            _serv: serv,
            mem: mem.deactivate(),
        })
    }
}

/*
use m3::kif::CapRngDesc;
use m3::kif::CapType;
use m3::server::CapExchange;
use m3::server::ClientManager;
use m3::server::ExcType;
use m3::server::SessId;

impl Session {
    /// Handler for the `get_mem` operation.
    fn get_mem(
        cli: &mut ClientManager<Self>,
        _crt: usize,
        sid: SessId,
        xchg: &mut CapExchange<'_>,
    ) -> Result<(), Error> {
        // We get the corresponding session of this request from the client manager.
        let sess: &mut Session = cli.get_mut(sid).expect("session not found");

        todo!("Send memory capability to client!");

        Ok(())
    }
}
*/

#[no_mangle]
pub fn main() -> Result<(), Error> {
    // A collection of handler functions registered to opcodes.
    let mut hdl: RequestHandler<Session, usize> =
        RequestHandler::new_with(DEF_MAX_CLIENTS, DEF_MSG_SIZE, 1)
            .expect("Unable to create request handler");
    // Server that creates new sessions.
    let srv = Server::new("sessions", &mut hdl).expect("Unable to create service");

    /* todo!("Register handler function!"); */

    // Endless sever loop reacting to new messages.
    server_loop(|| {
        // Let the server create new session and handle control messages.
        srv.fetch_and_handle(&mut hdl)?;

        // Let the handler handle message-only requests, which do not have any capabilities
        // exchanged.
        hdl.fetch_and_handle_msg();

        Ok(())
    })
}
