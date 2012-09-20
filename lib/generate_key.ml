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
open Cmdliner

let _ =
  let file = 
    let doc = "Output file for RSA key" in 
    Arg.(value & opt string "new.key" & info ["o"; "output"] ~docv:"FILE" ~doc)
  in
  let len = 
    let doc = "Key length in bits" in
    Arg.(value & opt int 256 & info ["l"; "length"] ~docv:"LENGTH" ~doc)
  in
  let cmd_t = Term.(pure Key.create_rsa_key $ file $ len) in
  let info =
    let doc = "Generate a fresh RSA key" in
    let man = [ `S "BUGS"; `P "Email bug reports to <cl-mirage@lists.cl.cam.ac.uk>."] in
    Term.info "generate_key" ~version:"0.3.0" ~doc ~man 
  in
  match Term.eval (cmd_t, info) with `Error _ -> exit 1 | _ -> exit 0
