mod rx;
use std::borrow::{Borrow, BorrowMut};

pub use rx::ChannelRx;

mod tx;
pub use tx::ChannelTx;
#[cfg(feature = "_test_hooks")]
pub use tx::{
    InvertParkGuard, S8bObjectClass, acquire_invert_bound2_discard_ready,
    acquire_invert_park_before_register, s8b_object_ack_before_register_round,
    s8b_object_register_round,
};

use crate::{Channel, ChannelId, ChannelMsg, ChannelReadHalf};

#[derive(Debug)]
pub struct ChannelCloseOnDrop<S: From<(ChannelId, ChannelMsg)> + Send + 'static>(pub Channel<S>);

impl<S: From<(ChannelId, ChannelMsg)> + Send + 'static> Borrow<ChannelReadHalf>
    for ChannelCloseOnDrop<S>
{
    fn borrow(&self) -> &ChannelReadHalf {
        &self.0.read_half
    }
}

impl<S: From<(ChannelId, ChannelMsg)> + Send + 'static> BorrowMut<ChannelReadHalf>
    for ChannelCloseOnDrop<S>
{
    fn borrow_mut(&mut self) -> &mut ChannelReadHalf {
        &mut self.0.read_half
    }
}

impl<S: From<(ChannelId, ChannelMsg)> + Send + 'static> Drop for ChannelCloseOnDrop<S> {
    fn drop(&mut self) {
        let id = self.0.write_half.id;
        let sender = self.0.write_half.sender.clone();

        // Best effort: async drop where possible
        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(async move {
            let _ = sender.send((id, ChannelMsg::Close).into()).await;
        });

        #[cfg(target_arch = "wasm32")]
        let _ = sender.try_send((id, ChannelMsg::Close).into());
    }
}
