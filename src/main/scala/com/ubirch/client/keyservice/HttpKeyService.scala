package com.ubirch.client.keyservice
import java.util.UUID

import org.json4s.DefaultFormats
import skinny.http.HTTP
import org.json4s.jackson.JsonMethods._

import scala.util.Try

class HttpKeyService(keyServiceUrl: String) extends KeyService {
  implicit private val formats: DefaultFormats = DefaultFormats

  override def getPublicKeys(uuid: UUID): List[KeyService.PublicKey] = {
    val response = HTTP.get(keyServiceUrl + "/api/keyService/v1/pubkey/current/hardwareId/" + uuid.toString)
    Try(parse(response.asString).extract[List[KeyService.PublicKey]]).getOrElse(List())
  }
}
