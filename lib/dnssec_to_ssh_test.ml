(* Demonstration of the Getopt module *)
open Key

let _ = 
  try 
    let domain_name = Sys.argv.(1) in 
      match (ssh_pub_key_of_domain domain_name) with
        | Some(keys) ->
            ssh_fingerprint_of_domain domain_name;
           Printf.printf "keys for domain %s: %s\n%!" domain_name (List.hd keys)
        | None ->
            Printf.printf "No keys found for domain\n%!"
  with a ->
     
    Printf.printf "bt:%s\n%s\nusage: ./%s domain_name\n%!" 
      (Printexc.get_backtrace ())
      (Printexc.to_string a) Sys.argv.(0) 
