open Rsa
open Lwt
open Packet 
module C = Cryptokit

exception Key_error of string
type key_type = 
    | PEM_PUB
    | PEM_PRIV
    | PEM_CERT
    | DNS_PUB
    | DNS_PRIV
let string_of_key_type = function
    | PEM_PUB -> "PEM_PUB" 
    | PEM_PRIV-> "PEM_PRIV"
    | PEM_CERT-> "PEM_CERT"
    | DNS_PUB -> "DNS_PUB"
    | DNS_PRIV-> "DNS_PRIV" 
let key_type_of_string = function
    |  "PEM_PUB" ->PEM_PUB 
    |  "PEM_PRIV"->PEM_PRIV
    |  "PEM_CERT"->PEM_CERT
    |  "DNS_PUB" ->DNS_PUB 
    |  "DNS_PRIV"->DNS_PRIV
    | a -> raise(Key_error(Printf.sprintf "error key type %s" a))


exception Action_error of string
type action_type = 
    | SIGN
    | TRANSFORM
    | VERIFY
let string_of_action_type = function
    | SIGN     -> "SIGN" 
    | TRANSFORM-> "TRANSFORM"
    | VERIFY   -> "VERIFY"
let action_type_of_strng = function
    | "SIGN"     ->  SIGN      
    | "TRANSFORM"->  TRANSFORM
    | "VERIFY"   ->  VERIFY   
    | a -> raise (Action_error (Printf.sprintf "error action: %s" a))

type key_conf = {
    mutable in_key: string;
    mutable in_ca_cert: string;
    mutable in_ca_priv: string;
    mutable in_type: key_type;
    mutable action : action_type;
    mutable cert_subj : string;
    mutable out_key : string;
    mutable out_type : key_type;
}

let process_dnskey_rr = function
    | `DNSKEY(_, RSAMD5, bits) 
    | `DNSKEY(_, RSASHA1, bits) 
    | `DNSKEY(_, RSASHA256, bits)
    | `DNSKEY(_, RSASHA512, bits) -> (
        Printf.printf "Found an RSA key\n%!";
        let rsa = Rsa.new_rsa_empty_key () in 
        bitmatch (Bitstring.bitstring_of_string bits) with 
        | {0:8;len:16; exp:len*8:string; modu:-1:string} ->
                Some({C.RSA.size = 0; C.RSA.n = modu;
                 C.RSA.e = exp; C.RSA.d = "";
                 C.RSA.p = ""; C.RSA.q = "";
                 C.RSA.dp = ""; C.RSA.dq = "";
                 C.RSA.qinv = "";})
        | {len:8;exp:len*8:string; modu:-1:string} ->
                Some({C.RSA.size = 0; C.RSA.n = modu;
                 C.RSA.e = exp; C.RSA.d = "";
                 C.RSA.p = ""; C.RSA.q = "";
                 C.RSA.dp = ""; C.RSA.dq = "";
                 C.RSA.qinv = "";})
        | { _ } -> Printf.printf "Invalid RSA DNSKEY format\n%!"; None
    )
    | `DNSKEY(_, _, bits) ->
            Printf.printf "We curently support only RSA cruptography\n%!";
            None
    | _ -> None

let get_dnssec_key domain =
    let ns_fd = (Unix.(socket PF_INET SOCK_DGRAM 0)) in
    let src = Unix.ADDR_INET(Unix.inet_addr_any, 25010) in
    Unix.bind ns_fd src;
    let detail = Packet.({qr=(qr_of_bool false); opcode=(opcode_of_int 0);
                aa=true; tc=false; rd=true; ra=false; rcode=(rcode_of_int 0);})
    in
    let question = Packet.({q_name=(Re_str.split (Re_str.regexp "\.") domain);
    q_type=(Packet.q_type_of_int 48);q_class=(Packet.q_class_of_int 0);}) in
    let packet = Packet.({id=1;detail=(Packet.build_detail detail);
    questions=[question]; answers=[]; authorities=[];
    additionals=[];}) in
    let data = Bitstring.string_of_bitstring (Packet.marshal packet) in

    (*TODO: define ns as a param *)
    let dst = Unix.ADDR_INET((Unix.inet_addr_of_string "8.8.8.8"),53) in
    let _ = Unix.sendto ns_fd data 0 (String.length data) [] dst in
    let buf = (String.create 1500) in
    let (len, _) = Unix.recvfrom ns_fd buf 0 1500 [] in
    let lbl = Hashtbl.create 64 in
    let reply = (Packet.parse_dns lbl
    (Bitstring.bitstring_of_string (String.sub buf 0 len))) in
(*     Printf.printf "dns reply: \n%s\n%!" (Packet.dns_to_string reply); *)
    if ( List.length reply.Packet.answers == 0) then
      None
    else
      process_dnskey_rr ((List.hd reply.Packet.answers).rr_rdata)

let decode_value value = 
    Base64.str_decode (Re_str.global_replace (Re_str.regexp "=") "" value)

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
            let line = Re_str.split (Re_str.regexp ": ") (input_line in_stream) in 
            match line with
            (* TODO: Need to check if this is an RSA key *)
            | "Modulus" :: value ->
                    n := decode_value (List.hd value); parse_file in_stream 
            | "PublicExponent" :: value ->
                    e := decode_value (List.hd value); parse_file in_stream             
            | "PrivateExponent" :: value ->
                    d := decode_value (List.hd value); parse_file in_stream             
            | "Prime1" :: value ->
                    p := decode_value (List.hd value); parse_file in_stream             
            | "Prime2" :: value ->
                    q := decode_value (List.hd value); parse_file in_stream             
            | "Exponent1" :: value ->
                    dp := decode_value (List.hd value); parse_file in_stream             
            | "Exponent2" :: value ->
                    dq:= decode_value (List.hd value); parse_file in_stream             
            | "Coefficient" :: value ->
                    qinv := decode_value (List.hd value); parse_file in_stream             
            | typ :: value ->
                    Printf.printf "read field:%s\n%!" typ; parse_file in_stream
        with  End_of_file -> ()
    in
    parse_file fd;
    C.RSA.({C.RSA.size = 0; C.RSA.n = !n; C.RSA.e = !e; C.RSA.d = !d;
    C.RSA.p = !p; C.RSA.q = !q; C.RSA.dp = !dp; C.RSA.dq = !dq;
    C.RSA.qinv = !qinv;})

let load_key file typ = 
    Printf.printf "makeloading key %s (%s)\n%!" file (string_of_key_type typ);
    match typ with 
    | PEM_PRIV -> 
            Some(Rsa.read_rsa_privkey file)
    | PEM_PUB -> 
            let key = Rsa.read_rsa_pubkey file in 
            print_rsa_key key;
            Some(key)
    | DNS_PUB -> (get_dnssec_key file)
    | PEM_CERT -> None
    | DNS_PRIV -> let key = (parse_dnssec_key file) in 
            print_rsa_key key; Some(key)

let convert_key conf =
    Printf.printf "converting key types...\n";
    let key = load_key conf.in_key conf.in_type in
    match key with 
    | Some(key) ->
            begin
                match conf.out_type with
                | PEM_PRIV -> Rsa.write_rsa_privkey conf.out_key key
                | PEM_PUB -> Rsa.write_rsa_pubkey conf.out_key key
                | DNS_PRIV -> (Printf.eprintf "lib doesn't support DNS_PRIV key generation\n")
                | DNS_PUB -> (Printf.eprintf "lib doesn't support DNS_PUB key generation\n")
                | PEM_CERT ->  (Printf.eprintf "lib doesn't support PEM_CERT\n")
                | _ -> ()
            end
    | None -> failwith "Failed to read input key"

let sign_key conf =
    Printf.printf "signing key...\n";
    let key = load_key conf.in_key conf.in_type in
    let sign_key = load_key conf.in_ca_priv PEM_PRIV in 
    match key with 
    | Some(key) ->
            begin
                match conf.out_type with
                | PEM_PRIV -> Rsa.write_rsa_privkey conf.out_key key
                | PEM_PUB -> Rsa.write_rsa_pubkey conf.out_key key
                | DNS_PRIV -> (Printf.eprintf "lib doesn't support DNS_PRIV key generation\n")
                | DNS_PUB -> (Printf.eprintf "lib doesn't support DNS_PUB key generation\n")
                | PEM_CERT ->  (Printf.eprintf "lib doesn't support PEM_CERT\n")
                | _ -> ()
            end
                | None -> failwith "Failed to read input key"

let process conf = 
    Printf.printf "processing keys...\n%!";
    match conf.action with 
    | TRANSFORM -> convert_key conf
    | SIGN -> sign_key conf
    | _ -> Printf.printf "Unsupported action %s" (string_of_action_type
    conf.action)


