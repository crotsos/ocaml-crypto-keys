(* Demonstration of the Getopt module *)
open Key
open Lwt

let fetch_data () = 
  try 
    let domain_name = Sys.argv.(1) in 
      lwt tmp = ssh_pub_key_of_domain domain_name in 
      match tmp with
        | Some(keys) ->
          lwt _ = ssh_fingerprint_of_domain domain_name in 
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

let _ =
  Lwt_main.run (fetch_data ())
