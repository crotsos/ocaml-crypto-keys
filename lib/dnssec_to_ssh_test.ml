(* Demonstration of the Getopt module *)
open Key
open Lwt

let fetch_data server_ip server_port domain_name =
  try 
    lwt tmp = ssh_pub_key_of_domain  ~server:server_ip ~port:server_port domain_name in 
    match tmp with
        | Some(keys) ->
          lwt _ = ssh_fingerprint_of_domain ~server:server_ip ~port:server_port domain_name in 
           Printf.printf "keys for domain %s: %s\n%!" domain_name (List.hd keys);
           return ()
        | None ->
            Printf.printf "No keys found for domain %s\n%!" domain_name;
            return ()
  with a -> 
    Printf.printf "bt:%s\n%s\nusage: ./%s domain_name\n%!" 
      (Printexc.get_backtrace ())
      (Printexc.to_string a) Sys.argv.(0) ;
      return ()

open Cmdliner

let lookup server port domain =
  Lwt_main.run (fetch_data server port domain)

let _ =
  let server = 
    let doc = "DNS server to perform the query against" in 
    Arg.(value & opt string "8.8.8.8" & info ["s"; "server"] ~docv:"SERVER" ~doc)
  in
  let port = 
    let doc = "UDP port to query" in
    Arg.(value & opt int 53 & info ["p"; "port"] ~docv:"PORT" ~doc)
  in
  let domain = 
    let doc = "Domain to query the SSH key for" in
    Arg.(value & pos 0 string "recoil.org" & info [] ~docv:"DOMAIN" ~doc)
  in
  let cmd_t = Term.(pure lookup $ server $ port $ domain) in
  let info =
    let doc = "do a DS lookup in SSH pubkey format" in
    let man = [ `S "BUGS"; `P "Email bug reports to <cl-mirage@lists.cl.cam.ac.uk>."] in
    Term.info "dnssec_to_ssh" ~version:"0.1.0" ~doc ~man 
  in
  match Term.eval (cmd_t, info) with `Error _ -> exit 1 | _ -> exit 0
