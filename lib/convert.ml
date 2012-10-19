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
open Printf
open Cmdliner

let enum_help keys =
  String.concat ", " (List.map (fun (x,y) -> sprintf "'%s'" (String.lowercase x)) keys)

let _ =
  let action =
    let doc = "Action to take on input key, which can be " ^ (enum_help Key.actions) in
    Arg.(value & pos 0 (enum Key.actions) Key.VERIFY & info [] ~docv:"ACTION" ~doc)
  in
  let in_key =
    let doc = "Ontput key file to convert" in
    Arg.(value & pos 1 string "/dev/stdin" & info [] ~docv:"INPUT" ~doc)
  in
  let in_type =
    let doc = "Input file type, which can be " ^ (enum_help Key.keys) in
    Arg.(value & pos 2 (enum Key.keys) Key.PEM_PUB & info [] ~docv:"IN_TYPE" ~doc)
  in
  let out_key =
    let doc = "Output key file" in
    Arg.(value & pos 3 string "/dev/stdout" & info [] ~docv:"OUTPUT" ~doc)
  in
  let out_type =
    let doc = "Output file type, which can be " ^ (enum_help Key.keys) in
    Arg.(value & pos 4 (enum Key.keys) Key.PEM_PUB & info [] ~docv:"OUT_TYPE" ~doc)
  in
  let issuer = 
    let doc = "Key Issuer name" in
    Arg.(value & opt string "" & info ["i";"issuer"] ~docv:"ISSUER" ~doc)
  in
  let ca_priv =
    let doc = "CA Private key" in
    Arg.(value & opt string "" & info ["p";"ca-priv"] ~docv:"CA_PRIV" ~doc)
  in
 let subj =
    let doc = "Key Subject" in
    Arg.(value & opt string "" & info ["s";"subject"] ~docv:"SUBJECT" ~doc)
  in
 let ns_ip =
    let doc = "server ip" in
    Arg.(value & opt string "23.23.179.30" & info ["S";"server"] ~docv:"SERVER" ~doc)
  in
 let ns_port =
    let doc = "server port" in
    Arg.(value & opt int 5354 & info ["P";"port"] ~docv:"PORT" ~doc)
  in
  let duration =
    Arg.(value & opt int 100 & info ["d";"duration"] ~docv:"DURATION" ~doc:"Key Duration")
  in
  let make_conf in_key in_type out_key out_type in_issuer in_ca_priv action cert_subj ns_ip ns_port duration =
    Key.({ in_key; in_issuer; in_ca_priv; in_type; action; cert_subj;out_key; out_type;
      duration; ns_ip;ns_port;}) in
  let cmd_t = Term.(pure make_conf $ in_key $ in_type $ out_key $ out_type $ issuer $ 
    ca_priv $ action $ subj $ ns_ip $ ns_port $ duration) in
  let info =
    let doc = "Convert between different key formats" in
    let man = [ `S "BUGS"; `P "Email bug reports to <cl-mirage@lists.cl.cam.ac.uk>."] in
    Term.info "convert" ~version:"0.3.0" ~doc ~man in
  let conf = match Term.eval (cmd_t, info) with `Ok x -> x | _ -> exit 1 in
  let _ = Lwt_unix.run (Key.process conf) in 
  Printf.printf "Process in key %s\n%!" conf.Key.in_key
