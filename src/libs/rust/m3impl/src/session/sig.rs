/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
 *
 * This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
 *
 * M3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * M3 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 */

use base::serialize::{Deserialize, Serialize};

use crate::col::{String, ToString};
use crate::com::{RecvGate, SendGate};
use crate::errors::Error;
use crate::int_enum;
use crate::session::ClientSession;

/// Represents a session at the signature server.
pub struct Sig {
    _sess: ClientSession,
    sgate: SendGate,
}

int_enum! {
    /// The signature-service operations.
    pub struct Operation : u64 {
        const GET_SGATE     = 1;
        const QUOTE         = 2;
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct QuoteReq {
    pub app: String,
    pub cfg: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct QuoteReply {
    pub quote: String,
}

impl Sig {
    /// Creates a new `Sig` session at service with given name.
    pub fn new(name: &str) -> Result<Self, Error> {
        let sess = ClientSession::new(name)?;
        let crd = sess.obtain(1, |os| os.push(Operation::GET_SGATE), |_| Ok(()))?;
        Ok(Sig {
            _sess: sess,
            sgate: SendGate::new_bind(crd.start()),
        })
    }

    /// Requests a quote for the given state, consisting of application and its configuration.
    pub fn quote(&self, app: &str, cfg: &str) -> Result<String, Error> {
        let reply: QuoteReply =
            send_recv_res!(&self.sgate, RecvGate::def(), Operation::QUOTE, QuoteReq {
                app: app.to_string(),
                cfg: cfg.to_string()
            })
            .and_then(|mut is| is.pop())?;
        Ok(reply.quote)
    }
}
