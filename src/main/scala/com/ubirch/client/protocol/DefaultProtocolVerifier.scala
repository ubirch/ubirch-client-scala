package com.ubirch.client.protocol

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.client.keyservice.PublicKeyProvider

class DefaultProtocolVerifier(keyService: PublicKeyProvider) extends MultiKeyProtocolVerifier(keyService) with StrictLogging