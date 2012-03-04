(*
    Copyright © 2011 MLstate

    This file is part of OPA.

    OPA is free software: you can redistribute it and/or modify it under the
    terms of the GNU Affero General Public License, version 3, as published by
    the Free Software Foundation.

    OPA is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
    more details.

    You should have received a copy of the GNU Affero General Public License
    along with OPA. If not, see <http://www.gnu.org/licenses/>.
*)

open Cryptokit

exception RSA_error

type rsa_key

(** Read an SSL RSA private key from a given file *)
val rsa_read_privkey : string -> rsa_key

(** Read an SSL RSA public key from a given file *)
val rsa_read_pubkey : string -> rsa_key

(** Convert an SSL RSA key to a Cryptokit RSA key format *)
val rsa_key_to_cryptokit_hex_rsa : rsa_key -> Cryptokit.RSA.key

(** Convert a [Ssl.ssl_error] to a string *)
(* val error_to_string : Ssl.ssl_error -> string *)

val new_rsa_empty_key : unit -> Cryptokit.RSA.key
val print_rsa_key: Cryptokit.RSA.key -> unit
val random_key: unit -> string
val read_rsa_privkey : string -> Cryptokit.RSA.key
val read_rsa_pubkey : string -> Cryptokit.RSA.key
