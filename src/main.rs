        Commands::Exec { sys, what, input } => {
            let system = sub.get_system(&sys)?;
            let workspace = match prepare_workspace(system) {
                Ok(ws) => Some(ws),
                Err(e) => {
                    // Fall back to no workspace if preparation fails
                    eprintln!("Warning: could not prepare workspace: {}", e);
                    None
                }
            };

            match exec_isolated(&what, input.as_deref(), &sys, workspace) {
                Ok(out) => {
                    if cli.json {
                        print_json(&serde_json::json!({"ok": true, "output": out}));
                    } else {
                        println!("{}", out);
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }