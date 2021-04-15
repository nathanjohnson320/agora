defmodule Agora.AccessKey do
  @moduledoc """
  Agora.AccessKey performs the algorithm used by the authentication mechanism in the Agora SDK
  version 2.1.0 or greater.

  ## Sample usage

  #### Server

      channel_name = "test"
      user = %{id: "12345asdf"}
      token = Agora.AccessKey.new_token(@app_id, @certificate, channel_name, user.id, [
        :join_channel,
        :publish_audio,
        :publish_video
      ])

  #### Client

      // Using agora-rtc-sdk-ng
      const client = AgoraRTC.createClient({ mode: 'live', codec: 'vp8' });
      await client.join(appId, 'test', token, '12345asdf');
      client.setClientRole('host');


  """
  use Bitwise

  @version "006"
  @privileges %{
    "kJoinChannel" => 1,
    "kPublishAudioStream" => 2,
    "kPublishVideoStream" => 3,
    "kPublishDataStream" => 4,
    "kPublishAudioCdn" => 5,
    "kPublishVideoCdn" => 6,
    "kRequestPublishAudioStream" => 7,
    "kRequestPublishVideoStream" => 8,
    "kRequestPublishDataStream" => 9,
    "kInvitePublishAudioStream" => 10,
    "kInvitePublishVideoStream" => 11,
    "kInvitePublishDataStream" => 12,
    "kAdministrateChannel" => 101,
    "kRtmLogin" => 1000
  }

  @doc """
  Return a map of all the raw privileges
  """
  @spec privileges :: %{optional(<<_::64, _::_*8>>) => 1..1000}
  def privileges, do: @privileges

  @doc """
  Get the integer value that agora assigns to a specific privilege.

  ## Examples

      iex> Agora.AccessKey.privilege(:join_channel)
      1

      iex> Agora.AccessKey.privilege(:publish_video)
      3

  """
  @spec privilege(atom) :: integer()
  def privilege(:join_channel), do: @privileges["kJoinChannel"]
  def privilege(:publish_audio), do: @privileges["kPublishAudioStream"]
  def privilege(:publish_video), do: @privileges["kPublishVideoStream"]
  def privilege(:publish_data), do: @privileges["kPublishDataStream"]
  def privilege(:publish_audio_cdn), do: @privileges["kPublishAudioCdn"]
  def privilege(:publish_video_cdn), do: @privileges["kPublishVideoCdn"]
  def privilege(:request_publish_audio), do: @privileges["kRequestPublishAudioStream"]
  def privilege(:request_publish_video), do: @privileges["kRequestPublishVideoStream"]
  def privilege(:request_publish_data), do: @privileges["kRequestPublishDataStream"]
  def privilege(:invite_publish_audio), do: @privileges["kInvitePublishAudioStream"]
  def privilege(:invite_publish_video), do: @privileges["kInvitePublishVideoStream"]
  def privilege(:invite_publish_data), do: @privileges["kInvitePublishDataStream"]
  def privilege(:administrate_channel), do: @privileges["kAdministrateChannel"]
  def privilege(:rtm_login), do: @privileges["kRtmLogin"]

  defp generate_message(salt, ts, privileges) do
    privileges_length = Enum.count(privileges)

    base =
      <<salt::unsigned-integer-size(32)-little, ts::unsigned-integer-size(32)-little,
        privileges_length::unsigned-integer-size(16)-little>>

    Enum.reduce(privileges, base, fn {privilege, expires_at}, acc ->
      privilege_code = privilege(privilege)

      privilege_binary = <<
        privilege_code::unsigned-integer-size(16)-little,
        expires_at::unsigned-integer-size(32)-little
      >>

      << acc :: bitstring >> <> privilege_binary
    end)
  end

  @doc """
  Generate a signed token that expires after 1 day

  ## Usage

      user = %{id: "12345"}
      token = Agora.new_token("970CA35de60c44645bbae8a215061b33", "5CFd2fd1755d40ecb72977518be15d3b", "7d72365eb983485397e3e3f9d460bdda", user.id, [
        :join_channel,
        :publish_audio,
        :publish_video,
        :request_publish_audio,
        :request_publish_video
      ])

  """
  @spec new_token(
          binary,
          binary,
          binary,
          binary,
          [atom()]
        ) :: binary()
  def new_token(app_id, app_certificate, channel_name, uid, privileges) do
    salt = Enum.random(0..100_000)

    date = DateTime.utc_now() |> DateTime.to_unix()
    # One day ahead
    ts = date + 24 * 3600

    # Auto set the privilege expiration
    privileges = for privilege <- privileges, do: {privilege, ts}

    generate_signed_token(app_id, app_certificate, channel_name, uid, privileges, salt, ts)
  end

  @doc """
  More direct way of generating tokens if you need to specify the salt and expiry manually.

  ## Examples

      iex> Agora.AccessKey.generate_signed_token("970CA35de60c44645bbae8a215061b33", "5CFd2fd1755d40ecb72977518be15d3b", "7d72365eb983485397e3e3f9d460bdda", "0", [{:join_channel, 1_446_455_471}], 1, 1_111_111)
      "006970CA35de60c44645bbae8a215061b33IABNRUO/126HmzFc+J8lQFfnkssUdUXqiePeE2WNZ7lyubdIfRAh39v0EAABAAAAR/QQAAEAAQCvKDdW"

  """
  @spec generate_signed_token(
          binary,
          binary,
          binary,
          binary,
          [{atom(), integer()}],
          integer(),
          integer()
        ) :: binary()
  def generate_signed_token(
        app_id,
        app_certificate,
        channel_name,
        uid,
        privileges,
        salt,
        ts
      ) do
    uid = if uid == 0, do: "", else: uid |> to_string()

    message = generate_message(salt, ts, privileges)
    message_length = byte_size(message)
    header = <<app_id::binary, channel_name::binary, uid::binary, message::binary>>
    signature = sign(app_certificate, header)
    signature_length = byte_size(signature)

    crc_channel_name = crc32(channel_name) &&& 0xFFFFFFFF
    crc_uid = crc32(uid) &&& 0xFFFFFFFF

    content =
      <<signature_length::unsigned-integer-size(16)-little, signature::binary,
        crc_channel_name::unsigned-integer-size(32)-little,
        crc_uid::unsigned-integer-size(32)-little,
        message_length::unsigned-integer-size(16)-little, message::binary>>
      |> Base.encode64()

    <<@version::binary, app_id::binary, content::binary>>
  end

  defp sign(key, value) do
    :crypto.hmac(:sha256, key, value)
  end

  defp crc32(data), do: :erlang.crc32(data)
end
