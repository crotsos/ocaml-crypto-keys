(* Demonstration of the Getopt module *)
open Key

let _ = 
  try 
    let domain_name = Sys.argv.(1) in 
      match (ssh_pub_key_of_domain domain_name) with
        | Some(keys) -> 
           Printf.printf "keys for domain %s: %s\n%!" domain_name (List.hd keys)
        | None ->
            Printf.printf "No keys found for domain\n%!"
  with exn ->
    Printf.printf "usage: ./%s domain_name\n%!" Sys.argv.(0) 
