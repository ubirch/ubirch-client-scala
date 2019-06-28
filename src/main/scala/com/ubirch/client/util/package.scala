package com.ubirch.client

package object util {
  def hexEncode(bytes: Array[Byte]): String = bytes.map("%02X".format(_)).mkString
}
