(*
 * Copyright (c) 2012 Charalampos Rotsos
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

open Key
open Lwt

let lookup verbose server port domain_name =
  let t = try_lwt
    match_lwt ssh_pub_key_of_domain ~server ~port domain_name with
    |Some keys ->
      lwt _ = ssh_fingerprint_of_domain ~server ~port domain_name in
      Printf.printf "%s:\n%s\n%!" domain_name (List.hd keys);
      exit 0
    |None ->
      Printf.eprintf "No keys found for domain %s\n%!" domain_name;
      exit 1
  with a -> 
    Printf.printf "bt:%s\n%s\nusage: ./%s domain_name\n%!" 
      (Printexc.get_backtrace ())
      (Printexc.to_string a) Sys.argv.(0) ;
      return ()
  in
  Lwt_main.run t

open Cmdliner

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
  let verbose = 
    let doc = "Verbose debug output" in
    Arg.(value & opt bool false & info ["v"; "verbose"] ~docv:"VERBOSE" ~doc)
  in
  let cmd_t = Term.(pure lookup $ verbose $ server $ port $ domain) in
  let info =
    let doc = "do a DS lookup in SSH pubkey format" in
    let man = [ `S "BUGS"; `P "Email bug reports to <cl-mirage@lists.cl.cam.ac.uk>."] in
    Term.info "dnssec_to_ssh" ~version:"0.1.0" ~doc ~man 
  in
  match Term.eval (cmd_t, info) with `Error _ -> exit 1 | _ -> exit 0
