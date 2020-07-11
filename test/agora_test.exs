defmodule Agora.AccessKeyTest do
  use ExUnit.Case
  doctest Agora.AccessKey

  alias Agora.AccessKey

  describe "generate_signed_token/1" do
    test "should create a valid signature" do
      app_id = "970CA35de60c44645bbae8a215061b33"
      app_certificate = "5CFd2fd1755d40ecb72977518be15d3b"
      channel_name = "7d72365eb983485397e3e3f9d460bdda"
      ts = 1_111_111
      salt = 1
      uid = "2882341273"
      expired_ts = 1_446_455_471

      expected =
        "006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW"

      assert AccessKey.generate_signed_token(
               app_id,
               app_certificate,
               channel_name,
               uid,
               [{:join_channel, expired_ts}],
               salt,
               ts
             ) == expected
    end

    test "should work with uid string 0" do
      app_id = "970CA35de60c44645bbae8a215061b33"
      app_certificate = "5CFd2fd1755d40ecb72977518be15d3b"
      channel_name = "7d72365eb983485397e3e3f9d460bdda"
      ts = 1_111_111
      salt = 1
      uid = "0"
      expired_ts = 1_446_455_471

      expected =
        "006970CA35de60c44645bbae8a215061b33IABNRUO/126HmzFc+J8lQFfnkssUdUXqiePeE2WNZ7lyubdIfRAh39v0EAABAAAAR/QQAAEAAQCvKDdW"

      assert AccessKey.generate_signed_token(
               app_id,
               app_certificate,
               channel_name,
               uid,
               [{:join_channel, expired_ts}],
               salt,
               ts
             ) == expected
    end

    test "should work with uid number 0" do
      app_id = "970CA35de60c44645bbae8a215061b33"
      app_certificate = "5CFd2fd1755d40ecb72977518be15d3b"
      channel_name = "7d72365eb983485397e3e3f9d460bdda"
      ts = 1_111_111
      salt = 1
      uid = 0
      expired_ts = 1_446_455_471

      expected =
        "006970CA35de60c44645bbae8a215061b33IACw1o7htY6ISdNRtku3p9tjTPi0jCKf9t49UHJhzCmL6bdIfRAAAAAAEAABAAAAR/QQAAEAAQCvKDdW"

      assert AccessKey.generate_signed_token(
               app_id,
               app_certificate,
               channel_name,
               uid,
               [{:join_channel, expired_ts}],
               salt,
               ts
             ) == expected
    end
  end
end
