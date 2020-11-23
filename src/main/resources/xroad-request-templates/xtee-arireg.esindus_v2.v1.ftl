<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xro="http://x-road.eu/xsd/xroad.xsd" xmlns:iden="http://x-road.eu/xsd/identifiers" xmlns:prod="http://arireg.x-road.eu/producer/">
   <soapenv:Header>
      <xro:protocolVersion>4.0</xro:protocolVersion>
      <xro:userId>EE${personIdCode}</xro:userId>
      <xro:id>${nonce}</xro:id>
      <xro:service iden:objectType="SERVICE">
         <iden:xRoadInstance>${serviceRoadInstance}</iden:xRoadInstance>
         <iden:memberClass>${serviceMemberClass}</iden:memberClass>
         <iden:memberCode>${serviceMemberCode}</iden:memberCode>
         <iden:subsystemCode>${serviceSubsystemCode}</iden:subsystemCode>
         <iden:serviceCode>esindus_v2</iden:serviceCode>
         <iden:serviceVersion>v1</iden:serviceVersion>
      </xro:service>
      <xro:client iden:objectType="SUBSYSTEM">
         <iden:xRoadInstance>${subsystemRoadInstance}</iden:xRoadInstance>
         <iden:memberClass>${subsystemMemberClass}</iden:memberClass>
         <iden:memberCode>${subsystemMemberCode}</iden:memberCode>
         <iden:subsystemCode>${subsystemSubsystemCode}</iden:subsystemCode>
      </xro:client>
   </soapenv:Header>
   <soapenv:Body>
      <prod:esindus_v2>
         <prod:keha>
                <prod:fyysilise_isiku_kood>${personIdCode}</prod:fyysilise_isiku_kood>
                <prod:fyysilise_isiku_koodi_riik>EST</prod:fyysilise_isiku_koodi_riik>
         </prod:keha>
      </prod:esindus_v2>
   </soapenv:Body>
</soapenv:Envelope>