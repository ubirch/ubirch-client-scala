package com.ubirch.client

import java.security.NoSuchAlgorithmException

import com.ubirch.crypto.utils.Curve

package object util {
  def hexEncode(bytes: Array[Byte]): String = bytes.map("%02X".format(_)).mkString

  def curveFromString(algorithm: String): Curve = algorithm match {
    case "ECC_ED25519" | "Ed25519" => Curve.Ed25519
    case "ECC_ECDSA" | "ecdsa-p256v1" | "ECDSA" => Curve.PRIME256V1
    case _ => throw new NoSuchAlgorithmException(s"Curve [$algorithm] not found")
  }
}
