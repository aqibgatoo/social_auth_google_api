<?php

namespace Drupal\social_auth_google_api\Controller;

use Drupal\Component\Serialization\Json;
use Drupal\user\Controller\UserAuthenticationController;
use GuzzleHttp\Exception\RequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * Provides controllers for login, login status and logout via HTTP requests.
 */
class GoogleUserAuthenticationController extends UserAuthenticationController {

  /**
   * Guzzle\Client instance.
   *
   * @var \GuzzleHttp\Client
   */
  protected $httpClient;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth_decoupled\SocialAuthDecoupledUserManager
   */
  protected $userManager;

  /**
   * Logs in a user.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A response which contains the ID and CSRF tokenzx
   */
  public function login(Request $request) {
    $format = $this->getRequestFormat($request);

    $content = $request->getContent();
    $credentials = $this->serializer->decode($content, $format);
    if (!isset($credentials['id_token'])) {
      throw new BadRequestHttpException('Missing id_token.');
    }
    $id_token = $credentials['id_token'];

    // Get user info from google by id_token.
    try {
      $response = $this->httpClient()
        ->request('GET', "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" . $id_token);
    }
    catch (RequestException $e) {
      throw new BadRequestHttpException($e->getMessage());
    }

    if ($response->getStatusCode() == 200) {
      $response_body_json = (string) $response->getBody();
      $user_info = Json::decode($response_body_json);
      $response_data = $this->socialAuthDecoupledUserManager()
        ->authenticateUser($user_info['email'], $user_info['name'], $user_info['sub'], $user_info['picture']);
      $encoded_response_data = $this->serializer->encode($response_data, $format);
      return new Response($encoded_response_data);
    }
    else {
      throw new BadRequestHttpException('Get info from google failed.');
    }
  }

  /**
   * Gets the social_auth_decoupled.user_manager.
   *
   * @return \Drupal\social_auth_decoupled\SocialAuthDecoupledUserManager
   *   The social_auth_decoupled.user_manager.
   */
  public function socialAuthDecoupledUserManager() {
    if (!isset($this->userManager)) {
      $this->userManager = \Drupal::getContainer()
        ->get('social_auth_decoupled.user_manager');
    }
    return $this->userManager;
  }

  /**
   * Gets the 'http_client' service.
   *
   * @return \GuzzleHttp\Client
   *   The 'http_client' service.
   */
  public function httpClient() {
    if (!isset($this->httpClient)) {
      $this->httpClient = \Drupal::getContainer()
        ->get('http_client');
    }
    return $this->httpClient;
  }

}
