use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug)]
pub struct JoinError;

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinError")
    }
}

impl std::error::Error for JoinError {}

pub struct JoinHandle<T>
where
    T: Send,
{
    handle: tokio::sync::oneshot::Receiver<T>,
}

#[cfg(target_arch = "wasm32")]
macro_rules! spawn_impl {
    ($fn:expr) => {
        wasm_bindgen_futures::spawn_local($fn)
    };
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! spawn_impl {
    ($fn:expr) => {
        tokio::spawn($fn)
    };
}

/// Poll `F` in place and send the output through `sender`.
///
/// The previous `async { let result = future.await; let _ = sender.send(result); }`
/// wrapper kept both the captured `future` and the `.await` awaitee
/// (~2× `size_of::<F>()`). SSH sessions are long-lived tokio tasks, so that
/// duplicate state sat in the task `Cell` for the whole session.
#[pin_project::pin_project]
struct Spawned<F: Future> {
    #[pin]
    fut: F,
    sender: Option<tokio::sync::oneshot::Sender<F::Output>>,
}

impl<F: Future> Future for Spawned<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.project();
        match this.fut.poll(cx) {
            Poll::Ready(result) => {
                if let Some(sender) = this.sender.take() {
                    let _ = sender.send(result);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub fn spawn<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static + Send,
    T: Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    spawn_impl!(Spawned {
        fut: future,
        sender: Some(sender),
    });
    JoinHandle { handle: receiver }
}

impl<T> Future for JoinHandle<T>
where
    T: Send,
{
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.handle).poll(cx) {
            Poll::Ready(Ok(val)) => Poll::Ready(Ok(val)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JoinError)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct BigFut([u8; 4096]);

    impl Future for BigFut {
        type Output = u8;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u8> {
            Poll::Ready(self.0[0])
        }
    }

    fn wrap_async_move_await<F: Future>(fut: F) -> impl Future<Output = ()>
    where
        F::Output: Send,
    {
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        async move {
            let result = fut.await;
            let _ = sender.send(result);
        }
    }

    #[test]
    fn spawn_future_does_not_duplicate_inner() {
        let inner = std::mem::size_of::<BigFut>();
        let async_wrap = std::mem::size_of_val(&wrap_async_move_await(BigFut([0; 4096])));
        let projected = std::mem::size_of::<Spawned<BigFut>>();
        eprintln!(
            "russh_util::spawn wrapper sizes (inner {inner}B):\n\
             \tasync {{ fut.await; sender.send }}  {async_wrap}\n\
             \tSpawned projection (chosen)         {projected}"
        );
        assert!(
            async_wrap >= inner * 2,
            "async-move-await should duplicate F: inner={inner} wrap={async_wrap}"
        );
        assert!(
            projected < inner + 64,
            "Spawned should be F + oneshot sender: inner={inner} wrap={projected}"
        );
        assert!(
            async_wrap - projected >= inner - 64,
            "projection must drop the duplicate F: inner={inner} async={async_wrap} spawned={projected}"
        );
    }

    #[tokio::test]
    async fn spawn_returns_output_and_drop_cancels_join() {
        let out = spawn(async { 42u8 }).await.unwrap();
        assert_eq!(out, 42);

        let pending = spawn(std::future::pending::<u8>());
        drop(pending);
        // Dropping JoinHandle only drops the oneshot receiver; the task itself
        // is detached (same as the previous async-block spawn).
    }

    #[tokio::test]
    async fn spawn_ready_after_yield() {
        let out = spawn(async {
            tokio::task::yield_now().await;
            7u8
        })
        .await
        .unwrap();
        assert_eq!(out, 7);
    }
}
