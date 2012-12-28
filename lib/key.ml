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

open Dns.Packet
open Rsa
open Lwt
open Printf
module C = Cryptokit

exception Key_error of string
type key_type = 
  | PEM_PUB
  | PEM_PRIV
  | PEM_CERT
  | DNS_PUB
  | DNS_PRIV
  | SSH_PUB
let string_of_key_type = function
  | PEM_PUB -> "PEM_PUB" 
  | PEM_PRIV-> "PEM_PRIV"
  | PEM_CERT-> "PEM_CERT"
  | DNS_PUB -> "DNS_PUB"
  | DNS_PRIV-> "DNS_PRIV"
  | SSH_PUB -> "SSH_PUB"
let key_type_of_string x =
  match String.uppercase x with
  |  "PEM_PUB" ->PEM_PUB 
  |  "PEM_PRIV"->PEM_PRIV
  |  "PEM_CERT"->PEM_CERT
  |  "DNS_PUB" ->DNS_PUB 
  |  "DNS_PRIV"->DNS_PRIV
  | "SSH_PUB" -> SSH_PUB
  | a -> raise(Key_error(Printf.sprintf "error key type %s" a))

let keys =
 List.map (fun x -> (string_of_key_type x, x))
   [ PEM_PUB; PEM_PRIV; PEM_CERT; DNS_PUB; DNS_PRIV; SSH_PUB ]

exception Action_error of string
type action_type = 
  | SIGN
  | TRANSFORM
  | VERIFY
let string_of_action_type = function
  | SIGN     -> "SIGN" 
  | TRANSFORM-> "TRANSFORM"
  | VERIFY   -> "VERIFY"
let action_type_of_strng x =
  match String.uppercase x with
  | "SIGN"     ->  SIGN      
  | "TRANSFORM"->  TRANSFORM
  | "VERIFY"   ->  VERIFY   
  | a -> raise (Action_error (Printf.sprintf "error action: %s" a))

let actions =
  List.map (fun x -> (string_of_action_type x, x))
    [ SIGN; TRANSFORM; VERIFY ]

type key_conf = {
  mutable in_key: string;
  (*     mutable in_ca_cert: string; *)
  mutable in_issuer: string;
  mutable in_ca_priv: string;
  mutable in_type: key_type;
  mutable action : action_type;
  mutable cert_subj : string;
  mutable out_key : string;
  mutable out_type : key_type;
  (* for cert only. how long the certificate will last. *)
  mutable duration : int;
  mutable ns_ip : string;
  mutable ns_port : int;
}

let process_dnskey_rr = function 
  | DNSKEY(_, _, bits) -> 
      let buf = Cstruct.of_bigarray (Lwt_bytes.of_string bits) in 
      let (exp, modu) = 
        match (Cstruct.get_uint8 buf 0) with
          | 0 -> 
              let len = Cstruct.BE.get_uint16 buf 1 in 
              let buf = Cstruct.shift buf 3 in 
              let e = Cstruct.to_string (Cstruct.sub buf 0 len) in 
              let buf = Cstruct.shift buf len in 
              let n = Cstruct.to_string buf in 
                (e, n)
          | len -> 
              let buf = Cstruct.shift buf 1 in 
              let e = Cstruct.to_string (Cstruct.sub buf 0 len) in 
              let buf = Cstruct.shift buf len in 
              let n = Cstruct.to_string buf in 
                (e, n)
      in
        Some( C.RSA.({size = 0;n = modu;e = exp; 
                      d = "";p = "";q = "";dp = "";
                      dq = "";qinv = "";}))
  | _ -> None

let marshal_rsa_key key = 
  let ret = Cstruct.create 4096 in
  let len = 
    if (String.length key.C.RSA.e > 255) then
      let _ = Cstruct.set_uint8 ret 0 0 in
      let _ = Cstruct.BE.set_uint16 ret 1 (String.length key.C.RSA.e) in
        3
    else 
      let _ = Cstruct.set_uint8 ret 0 (String.length key.C.RSA.e) in 
        1
  in
  let buf = Cstruct.shift ret len in 
  let _ = Cstruct.blit_from_string key.C.RSA.e 0 buf 0 (String.length key.C.RSA.e) in
  let buf = Cstruct.shift buf (String.length key.C.RSA.e) in 
  let _ = Cstruct.blit_from_string key.C.RSA.n 0 buf 0 (String.length key.C.RSA.n) in 
  let len = len + (String.length key.C.RSA.e) + (String.length key.C.RSA.n) in 
    Cstruct.to_string (Cstruct.sub ret 0 len)

let dns_pub_of_rsa key =
(*  let len = String.length key.C.RSA.e in 
  let key_rdata = 
    if (len <= 255) then 
      BITSTRING{len:8; (key.C.RSA.e):len*8:string; 
                        key.C.RSA.n:(String.length key.C.RSA.n)*8:string}
    else 
      BITSTRING{0:8; len:16; (key.C.RSA.e):len*8:string; 
                              key.C.RSA.n:(String.length key.C.RSA.n)*8:string}
  in *)
    sprintf "DNSKEY 256 3 5 %s" 
      (C.transform_string (C.Base64.encode_compact ()) 
         (marshal_rsa_key key))

let dnskey_rdata_of_rsa flag alg key =
(*  let len = String.length key.C.RSA.e in 
  let key_rdata = 
    if (len <= 255) then 
      BITSTRING{len:8; (key.C.RSA.e):len*8:string; 
                        key.C.RSA.n:(String.length key.C.RSA.n)*8:string}
    else 
      BITSTRING{0:8; len:16; (key.C.RSA.e):len*8:string; 
                              key.C.RSA.n:(String.length key.C.RSA.n)*8:string}
  in *)
    Dns.Packet.DNSKEY(flag, alg, 
         (marshal_rsa_key key))

let get_dnssec_key ?server:(server="128.232.1.1") 
      ?dns_port:(dns_port = 53) domain =
  try_lwt begin
    let open Dns.Packet in
    lwt t = Dns_resolver.create 
              ~config:(`Static([(server,dns_port)],[""])) () in 
    lwt reply = Dns_resolver.resolve t Q_IN Q_DNSKEY
        (Dns.Name.string_to_domain_name domain) 
    in
    let rec find_dnskey_rec = function
      | [] ->
          let _ = Printf.printf "Failed to get \n%!" in 
            return None
      | ans::_ when (Dns.Packet.rdata_to_rr_type ans.rdata = Dns.Packet.RR_DNSKEY ) ->
          let r = process_dnskey_rr ans.rdata in
            return r
      | _::ret -> 
          find_dnskey_rec ret
    in
      find_dnskey_rec reply.answers 
  end
  with e ->
    Printf.printf "failed to resolve name : %s\n%!" (Printexc.to_string e);
    return (None)

let decode_value value = 
  C.transform_string (C.Base64.decode ()) 
    (Re_str.global_replace (Re_str.regexp "=") "" value)

let parse_dnssec_key file =
  let n = ref "" in
  let e = ref "" in
  let d = ref "" in 
  let p = ref "" in
  let q = ref "" in 
  let dp = ref "" in 
  let dq = ref "" in 
  let qinv = ref "" in 
  let fd = open_in file in 
  let rec parse_file in_stream =
    try
      let line = Re_str.split (Re_str.regexp ": ") 
                   (input_line in_stream) in
      let _ = 
        match line with
          (* TODO: Need to check if this is an RSA key *)
          | "Modulus" :: value -> n := decode_value (List.hd value) 
          | "PublicExponent" :: value -> e := decode_value (List.hd value) 
          | "PrivateExponent" :: value -> d := decode_value (List.hd value) 
          | "Prime1" :: value -> p := decode_value (List.hd value) 
          | "Prime2" :: value -> q := decode_value (List.hd value) 
          | "Exponent1" :: value -> dp := decode_value (List.hd value) 
          | "Exponent2" :: value -> dq:= decode_value (List.hd value) 
          | "Coefficient" :: value -> qinv := decode_value (List.hd value)             
          | typ :: value -> printf "read field:%s\n%!" typ
          | [] -> ()
      in 
        parse_file in_stream
    with  End_of_file -> ()
  in
    parse_file fd;
    C.RSA.({size=0;n=(!n);e=(!e);d=(!d);
            p=(!p);q=(!q);dp=(!dp);dq=(!dq);
            qinv=(!qinv);})

let load_ssh_pub_key file =
(*  let n_val = ref "" in 
  let e_val = ref "" in *)
  let input = open_in file in 
  let buf = input_line input in
    close_in input;
    let key = (Cryptokit.(transform_string (Base64.decode ()) 
                            (List.nth (Re_str.split (Re_str.regexp " ") buf) 1))) in
    let buf = 
      Cstruct.of_bigarray (Lwt_bytes.of_string key) in
(*       Printf.printf "readine key %s \n%!" (Rsa.hex_of_string key); *)
(*      let _ = 
        bitmatch (Bitstring.bitstring_of_string key) with 
          | { "\x00\x00\x00\x07\x73\x73\x68\x2D\x72\x73\x61":88:string;
        ebytes:32; e:((Int32.to_int ebytes)*8):string;
                      nbytes:32; n:((Int32.to_int nbytes)*8):string; 
                                    _:-1:bitstring} -> 
              n_val := n; e_val := e;
(*               Printf.printf "Matched the string"; *)
          | { _ } -> Printf.printf "Cannot decode key \n%!";
      in *)
      let buf = Cstruct.shift buf 11 in 
      let e_len = Int32.to_int (Cstruct.BE.get_uint32 buf 0) in 
      let buf = Cstruct.shift buf 4 in 
      let e = Cstruct.to_string (Cstruct.sub buf 0 e_len) in 
      let buf = Cstruct.shift buf e_len in 
      let n = Cstruct.to_string buf in 
        C.RSA.({C.RSA.size = 0; C.RSA.n =n; C.RSA.e =e; C.RSA.d ="";
                C.RSA.p =""; C.RSA.q =""; C.RSA.dp =""; C.RSA.dq ="";
                C.RSA.qinv ="";})

let bitstring_ssh_pub_of_rsa key = 
  let e = 
    if (( (int_of_char (key.C.RSA.e.[0]))  land 0x80) != 0) then 
      ("\x00"  ^ key.C.RSA.e)
    else
      key.C.RSA.e   
  in
    let n =
      if (( (int_of_char (key.C.RSA.n.[0])) land 0x80) != 0) then
        ("\x00" ^ key.C.RSA.n)
      else
        key.C.RSA.n 
    in
    let buf = Cstruct.create 4096 in 
    let data = buf in 
    let _ = Cstruct.blit_from_string  "\x00\x00\x00\x07\x73\x73\x68\x2D\x72\x73\x61"
              0 buf 0 11 in 
    let buf = Cstruct.shift buf 11 in 
    let _ = Cstruct.BE.set_uint32 buf 0 (Int32.of_int (String.length e)) in 
    let buf = Cstruct.shift buf 4 in 
    let _ = Cstruct.blit_from_string e 0 buf 0 (String.length e) in 
    let buf = Cstruct.shift buf (String.length e) in 
    let _ = Cstruct.BE.set_uint32 buf 0 (Int32.of_int (String.length n)) in 
    let buf = Cstruct.shift buf 4 in 
    let _ = Cstruct.blit_from_string n 0 buf 0 (String.length n) in 
    let len = 11 + 8 + (String.length e) + (String.length n) in
      Cstruct.sub data 0 len 
(*    BITSTRING {
      "\x00\x00\x00\x07\x73\x73\x68\x2D\x72\x73\x61":88:string;
      (Int32.of_int (String.length e)):32; e:((String.length e)*8):string;
      (Int32.of_int (String.length n)):32; n:((String.length n)*8):string } *)
    
let ssh_pub_key_of_rsa key =
 let key_bin =  bitstring_ssh_pub_of_rsa key in
    let key_ssh = (C.transform_string (C.Base64.encode_compact()) 
      (Cstruct.to_string key_bin)) in 
      let ext_len = 
        if ( ((String.length key_ssh) mod 3) == 0) then 
          ""
        else 
          String.make (3 - ((String.length key_ssh) mod 3)) '='
      in 
        ("ssh-rsa " ^ key_ssh ^ ext_len ^ "\n")

let ssh_fingerprint_of_rsa key = 
 let key_bin =  bitstring_ssh_pub_of_rsa key in
 let hash = C.hash_string (Cryptokit.Hash.md5 ()) 
            (Cstruct.to_string key_bin) in
 let fingerprint = ref "" in 
   String.iter (fun ch -> 
               fingerprint := (Printf.sprintf "%s:%0x" (!fingerprint) 
                                 (int_of_char ch))) 
     hash;
  (!fingerprint)

let load_key server port file typ = 
  Printf.printf "loading key %s (%s)\n%!" file (string_of_key_type typ); 
  match typ with 
    | PEM_PRIV -> 
        return(Some(Rsa.read_rsa_privkey file))
    | PEM_PUB -> 
        return(Some(Rsa.read_rsa_pubkey file))
    | DNS_PUB -> (get_dnssec_key ~server:server ~dns_port:port file)
    | PEM_CERT -> return(None)
    | DNS_PRIV -> return(Some(parse_dnssec_key file))
    | SSH_PUB -> return (Some(load_ssh_pub_key file))
    | _ -> 
(*         Printf.eprintf "Invalid key type to read\n%!";  *)
        return(None)

let convert_key conf =
(*   Printf.printf "converting key types...\n"; *)
  lwt key = load_key conf.ns_ip conf.ns_port conf.in_key conf.in_type in
  match key with 
    | Some(key) ->
      begin
        match conf.out_type with
          | PEM_PRIV -> return(Rsa.write_rsa_privkey conf.out_key key)
          | PEM_PUB -> return(Rsa.write_rsa_pubkey conf.out_key key)
          | DNS_PRIV -> 
            return(Printf.eprintf "lib doesn't support DNS_PRIV key generation\n")
          | DNS_PUB -> 
              let str = dns_pub_of_rsa key in 
            let out_file = open_out conf.out_key in 
              output_string out_file (str ^ "\n");
              return (close_out out_file)                
          | PEM_CERT ->  return(Printf.eprintf "lib doesn't support PEM_CERT\n")
          | SSH_PUB -> 
            let str = ssh_pub_key_of_rsa key in 
            let out_file = open_out conf.out_key in 
              output_string out_file (str ^ "\n");
              return (close_out out_file) 
          | _ -> return (Printf.eprintf "Invalid key type to read\n%!")
      end
    | None -> failwith "Failed to read input key" 

let sign_key conf =
  Printf.printf "signing key...\n";
  lwt key = load_key  conf.ns_ip conf.ns_port conf.in_key conf.in_type in
  lwt sign_key = load_key  conf.ns_ip conf.ns_port conf.in_ca_priv PEM_PRIV in 
  (*     print_rsa_key sign_key; *)
  match (key, sign_key) with 
    | (Some(key), Some(sign_key)) ->
        begin
          match conf.out_type with
            | PEM_PRIV -> return(Rsa.write_rsa_privkey conf.out_key key)
            | PEM_PUB ->  return(Rsa.write_rsa_pubkey conf.out_key key)
            | DNS_PRIV ->  return(Printf.eprintf 
                                    "lib doesn't support DNS_PRIV key generation\n")
            | DNS_PUB -> return(Printf.eprintf 
                                  "lib doesn't support DNS_PUB key generation\n")
            | PEM_CERT -> 
               return(Rsa.sign_rsa_pub_key key sign_key conf.in_issuer 
                      conf.cert_subj conf.duration conf.out_key)
        end
    | (Some _ , None) -> 
        failwith "Failed to read signing key"
    | (None, Some _) -> 
        failwith "Failed to read input key"

let string_of_sign_key conf =
  Printf.printf "signing key...\n";
  lwt key = load_key  conf.ns_ip conf.ns_port conf.in_key conf.in_type in
  lwt sign_key = load_key  conf.ns_ip conf.ns_port conf.in_ca_priv PEM_PRIV in 
  (*     print_rsa_key sign_key; *)
  match (key, sign_key) with 
    | (Some(key), Some(sign_key)) ->
        begin
          match conf.out_type with
(*            | PEM_PRIV -> return(Rsa.write_rsa_privkey conf.out_key key)
            | PEM_PUB ->  return(Rsa.write_rsa_pubkey conf.out_key key)
            | DNS_PRIV ->  return(Printf.eprintf 
                                    "lib doesn't support DNS_PRIV key generation\n")
            | DNS_PUB -> return(Printf.eprintf 
                                  "lib doesn't support DNS_PUB key
                                  generation\n")*)
            | PEM_CERT -> 
               return(Rsa.string_of_sign_rsa_pub_key key sign_key conf.in_issuer 
                      conf.cert_subj conf.duration conf.out_key)
            | _ -> 
              failwith "Failed to sign key"
        end
    | (_, _) -> failwith "Failed to read input key"

let process conf = 
  match conf.action with 
    | TRANSFORM -> convert_key conf
    | SIGN -> sign_key conf
    | _ -> return (Printf.printf "Unsupported action %s" (string_of_action_type
                                                            conf.action))
let string_of_process conf = 
  match conf.action with 
    | TRANSFORM -> failwith "Unsupported action"
    | SIGN -> string_of_sign_key conf
    | _ -> failwith (Printf.sprintf "Unsupported action %s" 
                        (string_of_action_type conf.action))

let dnskey_of_pem_pub_file file =
  lwt tmp = load_key "" 0 file PEM_PUB in
  match tmp with
    | Some(key) -> 
        let ret = dns_pub_of_rsa key in 
          return (Some([ret]))
    | None -> return (None)

let dnskey_rdata_of_pem_pub_file file f a =
  lwt tmp = load_key "" 0 file PEM_PUB in
  match tmp with
    | Some(key) -> 
        return 
          (Some(dnskey_rdata_of_rsa f a key))
    | None -> return (None)
let dnskey_rdata_of_pem_priv_file file f a =
  lwt tmp = load_key "" 0 file PEM_PRIV in
  match tmp with
    | Some(key) -> 
        return 
          (Some(dnskey_rdata_of_rsa f a key))
    | None -> return (None)

let dnskey_of_pem_priv_file file =
  lwt tmp = load_key "" 0 file PEM_PRIV in
  match tmp with
  | Some(key) -> 
    let ret = dns_pub_of_rsa key in 
    return (Some([ret]))
  | None -> return (None)

let ssh_pub_key_of_domain  ?server:(server="128.232.1.1") 
?port:(port = 53) domain = 
  lwt tmp = get_dnssec_key ~server:server ~dns_port:port domain in 
  match (tmp) with
  | Some(key) -> 
    let ret = ssh_pub_key_of_rsa key in 
    return(Some([ret]))
  | None -> return(None)

let ssh_fingerprint_of_domain  ?server:(server="128.232.1.1") 
      ?port:(port=53) domain =                                        
  lwt tmp = get_dnssec_key ~server:server ~dns_port:port domain in
  match tmp with
    | Some(key) -> 
        let ret = ssh_fingerprint_of_rsa key in 
          return(Some([ret]))
    | None -> return(None)

let create_rsa_key file len = 
  Rsa.create_rsa_key file len

let load_rsa_priv_key file =
  Rsa.read_rsa_privkey file
