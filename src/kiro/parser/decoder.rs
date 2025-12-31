//! AWS Event Stream 流式解码器
//!
//! 使用状态机处理流式数据，支持断点续传和容错处理

use super::error::{ParseError, ParseResult};
use super::frame::{Frame, FrameParser};
use bytes::{Buf, BytesMut};

/// 解码器状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderState {
    /// 等待数据
    AwaitingData,
    /// 正在解析帧
    ParsingFrame,
    /// 发生错误，尝试恢复
    Recovering,
}

/// 流式事件解码器
///
/// 用于从字节流中解析 AWS Event Stream 消息帧
///
/// # Example
///
/// ```rust,ignore
/// use kiro_rs::kiro::parser::EventStreamDecoder;
///
/// let mut decoder = EventStreamDecoder::new();
///
/// // 提供流数据
/// decoder.feed(chunk);
///
/// // 解码所有可用帧
/// for result in decoder.decode_iter() {
///     match result {
///         Ok(frame) => println!("Got frame: {:?}", frame.event_type()),
///         Err(e) => eprintln!("Parse error: {}", e),
///     }
/// }
/// ```
pub struct EventStreamDecoder {
    /// 内部缓冲区
    buffer: BytesMut,
    /// 当前状态
    state: DecoderState,
    /// 已处理的帧数量
    frames_decoded: usize,
    /// 错误计数（用于容错限制）
    error_count: usize,
    /// 最大连续错误数
    max_errors: usize,
}

impl Default for EventStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStreamDecoder {
    /// 创建新的解码器
    pub fn new() -> Self {
        Self::with_capacity(8192)
    }

    /// 创建具有指定缓冲区大小的解码器
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
            state: DecoderState::AwaitingData,
            frames_decoded: 0,
            error_count: 0,
            max_errors: 10, // 默认最大连续错误数
        }
    }

    /// 向解码器提供数据
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        if self.state == DecoderState::Recovering {
            // 从恢复状态尝试继续
            self.state = DecoderState::AwaitingData;
        }
    }

    /// 尝试解码下一个帧
    ///
    /// # Returns
    /// - `Ok(Some(frame))` - 成功解码一个帧
    /// - `Ok(None)` - 数据不足，需要更多数据
    /// - `Err(e)` - 解码错误
    pub fn decode(&mut self) -> ParseResult<Option<Frame>> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        self.state = DecoderState::ParsingFrame;

        match FrameParser::parse(&self.buffer) {
            Ok(Some((frame, consumed))) => {
                // 消费已解析的字节
                self.buffer.advance(consumed);
                self.state = DecoderState::AwaitingData;
                self.frames_decoded += 1;
                self.error_count = 0; // 重置错误计数
                Ok(Some(frame))
            }
            Ok(None) => {
                self.state = DecoderState::AwaitingData;
                Ok(None)
            }
            Err(e) => {
                self.error_count += 1;

                // 检查是否超过最大错误数
                if self.error_count >= self.max_errors {
                    self.state = DecoderState::Recovering;
                    return Err(ParseError::HeaderParseFailed(format!(
                        "连续错误过多 ({})，停止解析: {}",
                        self.error_count, e
                    )));
                }

                // 尝试容错恢复：跳过一个字节
                self.try_recover();
                self.state = DecoderState::Recovering;
                Err(e)
            }
        }
    }

    /// 创建解码迭代器
    pub fn decode_iter(&mut self) -> DecodeIter<'_> {
        DecodeIter { decoder: self }
    }

    /// 尝试容错恢复
    ///
    /// 策略：跳过一个字节，尝试找到下一个有效消息边界
    fn try_recover(&mut self) {
        if !self.buffer.is_empty() {
            self.buffer.advance(1);
        }
    }
}

/// 解码迭代器
pub struct DecodeIter<'a> {
    decoder: &'a mut EventStreamDecoder,
}

impl<'a> Iterator for DecodeIter<'a> {
    type Item = ParseResult<Frame>;

    fn next(&mut self) -> Option<Self::Item> {
        // 如果处于恢复状态，停止迭代避免无限循环
        if self.decoder.state == DecoderState::Recovering {
            return None;
        }

        match self.decoder.decode() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decoder_feed() {
        let mut decoder = EventStreamDecoder::new();
        decoder.feed(&[1, 2, 3, 4]);
    }

    #[test]
    fn test_decoder_insufficient_data() {
        let mut decoder = EventStreamDecoder::new();
        decoder.feed(&[0u8; 10]); // 小于 prelude 大小

        let result = decoder.decode();
        assert!(matches!(result, Ok(None)));
    }
}
