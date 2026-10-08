use ratatui::{backend::TestBackend, Terminal};
use ratatui_image::picker::Picker;
use serde_json::{json, Value};
use shum_cli::ui::{draw, Pictures, View};
fn example() -> Value {
    json!({"profile":{"id":"local"},"card":{"name":"Игорь Загоев"},"relays":["wss://test.invalid"],"contacts":[{"id":"anna","card":{"name":"Аня","bio":"Дизайнер, люблю кофе и настолки.","avatarSeed":42},"unread":1,"nearby":false,"phase":"accepted","typing":true},{"id":"igor","card":{"name":"Игорь","avatarSeed":123},"phase":"incomingPending","unread":0}],"messages":[{"id":"m1","contactID":"anna","outgoing":false,"text":"Привет! Ты была на фестивале?","timestamp":1800000000000_i64,"status":"read"},{"id":"m2","contactID":"anna","outgoing":true,"text":"Да, у сцены с синтезаторами","timestamp":1800000100000_i64,"status":"read"}],"reactions":[{"messageID":"m2","mark":{"reaction":"like"}}]})
}
#[test]
fn tui_renders_chats_avatars_and_empty_state_in_small_terminals() {
    let mut pictures = Pictures::new(Picker::halfblocks());
    for (width, height) in [(80, 32), (40, 16), (140, 45)] {
        for ascii in [false, true] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut view = View::chat("anna");
            terminal
                .draw(|f| draw(f, &example(), &mut view, &mut pictures, ascii))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let screen = buffer
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("Аня"));
            assert!(screen.contains("Сообщение"));
            assert!(!screen.contains('\x1b'));
            if width == 80 && !ascii {
                assert!(screen.contains("синтезаторами"));
                assert!(screen.contains("like"));
                if let Ok(path) = std::env::var("SHUM_TEST_SCREEN") {
                    let cells=buffer.content.iter().map(|c|json!({"s":c.symbol(),"fg":format!("{:?}",c.fg),"bg":format!("{:?}",c.bg)})).collect::<Vec<_>>();
                    std::fs::write(
                        path,
                        serde_json::to_vec(&json!({"width":width,"height":height,"cells":cells}))
                            .unwrap(),
                    )
                    .unwrap();
                }
            }
            view.opened = None;
            terminal
                .draw(|f| {
                    draw(
                        f,
                        &json!({"card":{"name":"Игорь"}}),
                        &mut view,
                        &mut pictures,
                        ascii,
                    )
                })
                .unwrap();
            let screen = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("QR"));
        }
    }
}
