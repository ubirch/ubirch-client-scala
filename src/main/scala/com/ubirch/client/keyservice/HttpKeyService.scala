package com.ubirch.client.keyservice

import java.util.{Base64, UUID}

import com.ubirch.client.keyservice.HttpKeyService._
import org.json4s.DefaultFormats
import skinny.http.HTTP
import org.json4s.jackson.JsonMethods._
import com.ubirch.client.util._
import com.ubirch.crypto.{GeneratorKeyFactory, PubKey}

import scala.util.Try

class HttpKeyService(keyServiceUrl: String) extends KeyService {
  implicit private val formats: DefaultFormats = DefaultFormats

  override def getPublicKeys(uuid: UUID): List[PubKey] = {
    val response = HTTP.get(keyServiceUrl + "/api/keyService/v1/pubkey/current/hardwareId/" + uuid.toString)
    Try(parse(response.asString).extract[List[PublicKey]]).getOrElse(List())
      .map { case PublicKey(PublicKeyInfo(pubKey, algorithm)) =>
        val curve = curveFromString(algorithm)
        val bytes = Base64.getDecoder.decode(pubKey)
        GeneratorKeyFactory.getPubKey(bytes, curve)
      }
  }
}

object HttpKeyService {

  case class PublicKey(pubKeyInfo: PublicKeyInfo)

  case class PublicKeyInfo(
    /** base64 encoded */
    pubKey: String,
    algorithm: String
  )

}
