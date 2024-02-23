export const dash1 = `<?xml version="1.0" encoding="utf-8"?>
<MPD xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:mpeg:dash:schema:mpd:2011"
   xsi:schemaLocation="urn:mpeg:dash:schema:mpd:2011 http://standards.iso.org/ittf/PubliclyAvailableStandards/MPEG-DASH_schema_files/DASH-MPD.xsd"
   type="static" mediaPresentationDuration="PT12M14S" minBufferTime="PT10S"
   profiles="urn:mpeg:dash:profile:isoff-on-demand:2011">
  <Period duration="PT12M14S">
    <AdaptationSet id="1" group="1" contentType="audio" lang="en" minBandwidth="64349" maxBandwidth="128407"
             segmentAlignment="true" subsegmentAlignment="true" subsegmentStartsWithSAP="1"
             audioSamplingRate="48000" mimeType="audio/mp4" codecs="mp4a.40.2" startWithSAP="1">
      <AudioChannelConfiguration schemeIdUri="urn:mpeg:dash:23003:3:audio_channel_configuration:2011"
                     value="2"></AudioChannelConfiguration>
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="main"/>
      <Representation id="audio_eng=64349" bandwidth="64349">
        <BaseURL>tears-of-steel-aac-64k.cmfa</BaseURL>
        <SegmentBase timescale="48000" indexRangeExact="true" indexRange="704-2211">
          <Initialization range="0-703"/>
        </SegmentBase>
      </Representation>
      <Representation id="audio_eng=128407" bandwidth="128407">
        <BaseURL>tears-of-steel-aac-128k.cmfa</BaseURL>
        <SegmentBase timescale="48000" indexRangeExact="true" indexRange="704-2211">
          <Initialization range="0-703"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="2" group="3" contentType="text" lang="en" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_eng=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-en.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="607-1778">
          <Initialization range="0-606"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="3" group="3" contentType="text" lang="de" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_deu=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-de.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="607-1778">
          <Initialization range="0-606"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="4" group="3" contentType="text" lang="es" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_spa=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-es.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="607-1778">
          <Initialization range="0-606"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="5" group="3" contentType="text" lang="fr" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_fra=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-fr.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="607-1778">
          <Initialization range="0-606"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="6" group="3" contentType="text" lang="nl" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_nld=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-nl.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="607-1778">
          <Initialization range="0-606"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="7" group="3" contentType="text" lang="pt-br" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_pt-br=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-pt-br.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="625-1796">
          <Initialization range="0-624"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="8" group="3" contentType="text" lang="pt-pt" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_pt-pt=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-pt-pt.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="625-1796">
          <Initialization range="0-624"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="9" group="3" contentType="text" lang="ru" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_rus=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-ru.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="607-1778">
          <Initialization range="0-606"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="10" group="3" contentType="text" lang="zh" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_zho=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-zh.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="607-1778">
          <Initialization range="0-606"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="11" group="3" contentType="text" lang="zh-hans" subsegmentAlignment="true"
             subsegmentStartsWithSAP="1" mimeType="application/mp4" codecs="wvtt" startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="subtitle"/>
      <Representation id="textstream_zh-hans=1000" bandwidth="1000">
        <BaseURL>tears-of-steel-zh-hans.cmft</BaseURL>
        <SegmentBase timescale="1000" indexRangeExact="true" indexRange="627-1798">
          <Initialization range="0-626"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="12" group="2" contentType="video" lang="en" par="56:25" minBandwidth="405000"
             maxBandwidth="2205000" maxWidth="1680" maxHeight="750" segmentAlignment="true"
             subsegmentAlignment="true" subsegmentStartsWithSAP="1" sar="1:1" mimeType="video/mp4"
             startWithSAP="1">
      <Role schemeIdUri="urn:mpeg:dash:role:2011" value="main"/>
      <Representation id="video_eng=405000" bandwidth="405000" width="224" height="100" codecs="avc1.64001F"
              scanType="progressive">
        <BaseURL>tears-of-steel-avc1-400k.cmfv</BaseURL>
        <SegmentBase timescale="12288" indexRangeExact="true" indexRange="761-1896">
          <Initialization range="0-760"/>
        </SegmentBase>
      </Representation>
      <Representation id="video_eng=759000" bandwidth="759000" width="448" height="200" codecs="avc1.64001F"
              scanType="progressive">
        <BaseURL>tears-of-steel-avc1-750k.cmfv</BaseURL>
        <SegmentBase timescale="12288" indexRangeExact="true" indexRange="760-1895">
          <Initialization range="0-759"/>
        </SegmentBase>
      </Representation>
      <Representation id="video_eng=1026000" bandwidth="1026000" width="784" height="350" codecs="avc1.64001F"
              scanType="progressive">
        <BaseURL>tears-of-steel-avc1-1000k.cmfv</BaseURL>
        <SegmentBase timescale="12288" indexRangeExact="true" indexRange="761-1896">
          <Initialization range="0-760"/>
        </SegmentBase>
      </Representation>
      <Representation id="video_eng=1501000" bandwidth="1501000" width="1680" height="750" codecs="avc1.640028"
              scanType="progressive">
        <BaseURL>tears-of-steel-avc1-1500k.cmfv</BaseURL>
        <SegmentBase timescale="12288" indexRangeExact="true" indexRange="762-1897">
          <Initialization range="0-761"/>
        </SegmentBase>
      </Representation>
      <Representation id="video_eng=2205000" bandwidth="2205000" width="1680" height="750" codecs="avc1.640028"
              scanType="progressive">
        <BaseURL>tears-of-steel-avc1-2200k.cmfv</BaseURL>
        <SegmentBase timescale="12288" indexRangeExact="true" indexRange="762-1897">
          <Initialization range="0-761"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>`;
