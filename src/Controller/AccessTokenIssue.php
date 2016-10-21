<?php

namespace Drupal\simple_oauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\user\UserAuthInterface;
use Drupal\simple_oauth\Entity\AccessToken;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;


class AccessTokenIssue extends ControllerBase {

  /**
   * The user authentication object.
   *
   * @var \Drupal\user\UserAuthInterface
   */
  protected $userAuth;

  /**
   * The response object.
   *
   * @var JsonResponse
   */
  protected $response;

  /**
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   *   The entity manager service.
   */
  public function __construct(EntityManagerInterface $entity_manager, UserAuthInterface $user_auth, JsonResponse $response) {
    $this->entityManager = $entity_manager;
    $this->userAuth = $user_auth;
    $this->response = $response;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('entity.manager'),
      $container->get('user.auth'),
      new JsonResponse()
    );
  }


  public function issue(Request $request) {
    $body = json_decode($request->getContent());

    if (!$body->grant_type == 'password') {
      $this->response->setStatusCode(422);
      $this->response->setData([
        "error" => "Only grant_type=password is supported"
      ]);
      return $this->response;
    }

    $scope = 'global';
    if ($body->scope) {
      $scope = $body->scope;
      $resource = $this->entityManager->getStorage('access_token_resource')->load($scope);
      if (!$resource) {
        $this->response->setStatusCode(422);
        $this->response->setData([
          "error" => "Unknown scope " . $scope
        ]);
        return $this->response;
      }
    }

    $uid = $this->userAuth->authenticate($body->username, $body->password);
    if ($uid) {
      $values = [
        'expire' => AccessToken::defaultExpiration(),
        'user_id' => $uid,
        'auth_user_id' => $uid,
        'resource' => $scope,
      ];
      $store = $this->entityManager->getStorage('access_token');
      $token = $store->create($values);
      $token->save();
      $this->response->setData($this->normalize($token));
    } else {
      $this->response->setStatusCode(401);
    }
    return $this->response;
  }

  protected function normalize(AccessToken $token) {
    $storage = $this->entityManager()->getStorage('access_token');
    $ids = $storage
      ->getQuery()
      ->condition('access_token_id', $token->id())
      ->condition('expire', REQUEST_TIME, '>')
      ->condition('resource', 'authentication')
      ->range(0, 1)
      ->execute();
    if (!empty($ids)) {
      $refresh_token = $storage->load(reset($ids))->get('value')->value;
    }
    return [
      'access_token' => $token->get('value')->value,
      'token_type' => 'Bearer',
      'expires_in' => $token->get('expire')->value - REQUEST_TIME,
      'refresh_token' => $refresh_token,
    ];
  }


}
