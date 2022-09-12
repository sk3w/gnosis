use clap::Parser;
use gnosis::Proxy;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Local GNS listener port
    #[clap(short, long, value_parser)]
    listen_addr: SocketAddr,

    /// Remote GNS server address
    #[clap(short, long, value_parser)]
    remote_addr: SocketAddr,

    /// Client Steam ID
    #[clap(long, value_parser)]
    client_steam_id: u64,

    /// Server Steam ID
    #[clap(long, value_parser)]
    server_steam_id: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    env_logger::init();
    let proxy = Proxy::new(
        args.listen_addr,
        args.remote_addr,
        args.client_steam_id,
        args.server_steam_id,
    )
    .await
    .unwrap();
    proxy.run().await.unwrap();
    //ui::main(proxy.get_stats()).unwrap();
    //ui::main(Arc::new(Mutex::new(ProxyStats::new()))).unwrap();
    println!("Done!");
}

mod ui {
    use std::{io, sync::Arc, thread, time::Duration};

    use crossterm::{
        event::DisableMouseCapture,
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, LeaveAlternateScreen},
    };
    use gnosis::ProxyStats;
    use tokio::sync::Mutex;
    use tui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        widgets::{Block, Borders},
        Terminal,
    };

    pub fn main(stats: Arc<Mutex<ProxyStats>>) -> Result<(), io::Error> {
        enable_raw_mode().expect("Raw mode is available in terminal");
        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;

        //tui_logger::init_logger(log::LevelFilter::Debug).unwrap();
        //tui_logger::set_default_level(log::LevelFilter::Debug);

        loop {
            terminal.draw(|rect| {
                let size = rect.size();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(3),
                            Constraint::Min(2),
                            Constraint::Max(3),
                        ]
                        .as_ref(),
                    )
                    .split(size);
                // let table = Table::new(vec![
                //     Row::new(vec!["Passed downstream", "0"]),
                //     Row::new(vec!["Passed upstream", "0"]),
                // ]);
                //rect.render_widget(table, chunks[0]);
                let block = Block::default().title("gns-proxy").borders(Borders::ALL);
                rect.render_widget(block, chunks[0]);
            })?;
            thread::sleep(Duration::from_millis(3000));
            break;
        }
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        Ok(())
    }
}
