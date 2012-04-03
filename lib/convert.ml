open Key
open Getopt
open Lwt

let conf = Key.({
    in_key="test.pem";in_issuer="";in_ca_priv="";in_type=PEM_PUB;action=TRANSFORM;
    cert_subj="";out_key="";out_type=PEM_PUB; duration=100;
    ns_ip="172.16.11.1";ns_port=5354})

let specs = 
    [
        (* (short_name * long_name * how_to_handle_flags *
         * how_to_handle_argument *)
        ('k', "in_key", None, Some (fun x -> conf.Key.in_key <- x));
(*         ('c', "ca_cert", None, Some (fun x -> conf.Key.in_ca_cert <- x)); *)
        ('i', "issuer", None, Some (fun x -> conf.Key.in_issuer <- x));
        ('p', "ca_priv", None, Some (fun x -> conf.Key.in_ca_priv <- x));
        ('t', "in_type", None, Some (fun x -> conf.Key.in_type <- (Key.key_type_of_string
        (String.uppercase x))));
        ('a', "action", None, Some(fun x -> conf.Key.action <-
            (Key.action_type_of_strng (String.uppercase x))));
        ( 's', "cert_subj", None, Some (fun x -> conf.Key.cert_subj <- x));
        ('K', "out_key", None, Some (fun x -> conf.Key.out_key <- x));
        ('T', "out_type", None, Some(fun x ->  conf.Key.out_type <-
            (Key.key_type_of_string(String.uppercase x)) ) );
            ('D', "duration", None, Some (fun x -> conf.Key.duration <-
                (int_of_string x)));

]

lwt _ = 
    parse_cmdline specs print_endline;
    lwt _ = Key.process conf in 
      return (Printf.printf "Process in key %s\n%!" conf.Key.in_key)
