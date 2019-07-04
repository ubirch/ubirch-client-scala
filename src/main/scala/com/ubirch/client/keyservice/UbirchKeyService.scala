package com.ubirch.client.keyservice

import java.util.{Base64, UUID}

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.client.keyservice.UbirchKeyService._
import org.json4s.DefaultFormats
import skinny.http.HTTP
import org.json4s.jackson.JsonMethods._
import com.ubirch.client.util._
import com.ubirch.crypto.{GeneratorKeyFactory, PubKey}

import scala.util.Try

class UbirchKeyService(keyServiceUrl: String) extends PublicKeyProvider with StrictLogging {
  implicit private val formats: DefaultFormats = DefaultFormats

  override def getPublicKey(uuid: UUID): Option[PubKey] = {
    val url = keyServiceUrl + "/api/keyService/v1/pubkey/current/hardwareId/" + uuid.toString
    logger.debug(s"Making HTTP Get request to [$url]")
    val response = HTTP.get(url).asString
    logger.debug(s"response: [$response]")
    Try(parse(response).extract[List[PublicKey]]).getOrElse(List())
      .map { case PublicKey(PublicKeyInfo(pubKey, algorithm)) =>
        val curve = curveFromString(algorithm)
        val bytes = Base64.getDecoder.decode(pubKey)
        GeneratorKeyFactory.getPubKey(bytes, curve)
      }.headOption
  }
}

object UbirchKeyService {

  case class PublicKey(pubKeyInfo: PublicKeyInfo)

  case class PublicKeyInfo(
    /** base64 encoded */
    pubKey: String,
    algorithm: String
  )

}
