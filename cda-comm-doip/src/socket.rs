/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::net::SocketAddr;

use doip_codec::DoipCodec;
use doip_definitions::{
    builder::DoipMessageBuilder,
    header::ProtocolVersion,
    message::DoipMessage,
    payload::{DiagnosticAckCode, DiagnosticMessageAck, DoipPayload},
};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_util::{
    codec::{Framed, FramedRead, FramedWrite},
    udp::UdpFramed,
};

use crate::ConnectionError;

pub(crate) struct DoIPConnection<T: AsyncRead + AsyncWrite + Unpin> {
    io: Framed<T, DoipCodec>,
    protocol: doip_definitions::header::ProtocolVersion,
}

impl<T: AsyncRead + AsyncWrite + Unpin> DoIPConnection<T> {
    pub fn new(io: T) -> Self {
        Self {
            io: Framed::new(io, DoipCodec {}),
            protocol: ProtocolVersion::Iso13400_2012,
        }
    }
    pub async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError> {
        send_doip(&mut self.io, self.protocol, msg).await
    }
    pub async fn read(&mut self) -> Option<Result<DoipMessage, ConnectionError>> {
        let res = read_doip(&mut self.io).await;
        if let Some(Ok(ref msg)) = res
            && let DoipPayload::DiagnosticMessage(ref diag_msg) = msg.payload
            && let Err(e) = self
                .send(DoipPayload::DiagnosticMessageAck(DiagnosticMessageAck {
                    source_address: diag_msg.target_address,
                    target_address: diag_msg.source_address,
                    ack_code: DiagnosticAckCode::Acknowledged,
                    previous_message: Vec::new(), // skip optional previous payload
                }))
                .await
        {
            return Some(Err(ConnectionError::SendFailed(format!(
                "Failed to send DiagnosticMessageAck: {e}",
            ))));
        }

        res
    }
    pub fn into_split(self) -> (DoIPConnectionReadHalf<T>, DoIPConnectionWriteHalf<T>) {
        let stream = self.io.into_inner();

        let (read, write) = tokio::io::split(stream);
        (
            DoIPConnectionReadHalf::new(read),
            DoIPConnectionWriteHalf::new(write, self.protocol),
        )
    }
}
pub(crate) struct DoIPConnectionReadHalf<T: AsyncRead + Unpin> {
    io: FramedRead<ReadHalf<T>, DoipCodec>,
}
pub(crate) struct DoIPConnectionWriteHalf<T: AsyncWrite + Unpin> {
    io: FramedWrite<WriteHalf<T>, DoipCodec>,
    protocol: ProtocolVersion,
}

impl<T: AsyncWrite + Unpin> DoIPConnectionWriteHalf<T> {
    pub fn new(io: WriteHalf<T>, protocol: ProtocolVersion) -> Self {
        Self {
            io: FramedWrite::new(io, DoipCodec {}),
            protocol,
        }
    }

    pub async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError> {
        send_doip(&mut self.io, self.protocol, msg).await
    }
}
impl<T: AsyncRead + Unpin> DoIPConnectionReadHalf<T> {
    pub fn new(io: ReadHalf<T>) -> Self {
        Self {
            io: FramedRead::new(io, DoipCodec {}),
        }
    }
    pub async fn read(&mut self) -> Option<Result<DoipMessage, ConnectionError>> {
        read_doip(&mut self.io).await
    }
}

pub(crate) struct DoIPUdpSocket {
    io: UdpFramed<DoipCodec, tokio::net::UdpSocket>,
    protocol_version: ProtocolVersion,
}

impl DoIPUdpSocket {
    pub fn new(socket: std::net::UdpSocket) -> Result<Self, std::io::Error> {
        let tokio_socket = tokio::net::UdpSocket::from_std(socket)?;
        Ok(Self {
            io: UdpFramed::new(tokio_socket, DoipCodec {}),
            protocol_version: ProtocolVersion::Iso13400_2012,
        })
    }

    pub async fn send(
        &mut self,
        payload: DoipPayload,
        addr: SocketAddr,
    ) -> Result<(), ConnectionError> {
        let msg = DoipMessageBuilder::new()
            .protocol_version(self.protocol_version)
            .payload(payload)
            .build();
        self.io
            .send((msg, addr))
            .await
            .map_err(|e| ConnectionError::SendFailed(format!("Failed to send message: {e:?}")))
    }

    pub async fn recv(&mut self) -> Option<Result<(DoipMessage, SocketAddr), ConnectionError>> {
        self.io.next().await.map(|opt| {
            opt.map_err(|e| ConnectionError::Decoding(format!("Failed to read message: {e:?}")))
        })
    }
}

async fn send_doip<T: SinkExt<DoipMessage, Error = doip_codec::Error> + Unpin>(
    io: &mut T,
    protocol: ProtocolVersion,
    msg: DoipPayload,
) -> Result<(), ConnectionError> {
    let msg = DoipMessageBuilder::new()
        .protocol_version(protocol)
        .payload(msg)
        .build();

    io.send(msg)
        .await
        .map_err(|e| ConnectionError::SendFailed(format!("Failed to send message: {e:?}")))
}

async fn read_doip<T: StreamExt<Item = Result<DoipMessage, doip_codec::Error>> + Unpin>(
    io: &mut T,
) -> Option<Result<DoipMessage, ConnectionError>> {
    io.next().await.map(|opt| {
        opt.map_err(|e| ConnectionError::Decoding(format!("Failed to read message: {e:?}")))
    })
}
