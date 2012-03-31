open Key
open Getopt


let _ =
  let file = Sys.argv.(1) in 
  let len = int_of_string Sys.argv.(2) in 
  Printf.printf "creatiing new rsa key...\n%!";
  let ret = Key.create_rsa_key file len in 
  ()
